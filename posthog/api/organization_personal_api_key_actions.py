from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence

from django.db import transaction

from posthog.api.personal_api_key import PersonalAPIKeySerializer
from posthog.dataclasses import frozen
from posthog.enums import LabeledStrEnum
from posthog.models import Organization, OrganizationMembership, Team, User
from posthog.models.activity_logging.model_activity import ActingUserContext
from posthog.models.activity_logging.personal_api_key_utils import OrganizationAdminKeyActionContext
from posthog.models.personal_api_key import (
    PersonalAPIKey,
    get_organization_ids_in_key_scope,
    get_organization_personal_api_keys,
)


@frozen
class PersonalAPIKeyOrganizationAccess:
    has_access_to_organization: bool
    other_organization_ids: frozenset[str]


class PersonalAPIKeyOrganizationAccessResolver:
    """A key reaches the organizations that `get_organization_ids_in_key_scope` allows and the owner is a member of.
    An organization the owner left never counts."""

    def __init__(
        self, *, member_organization_ids: Mapping[int, frozenset[str]], team_organization_ids: Mapping[int, str]
    ) -> None:
        self._member_organization_ids = member_organization_ids
        self.team_organization_ids = team_organization_ids

    @classmethod
    def for_keys(cls, keys: Sequence[PersonalAPIKey]) -> "PersonalAPIKeyOrganizationAccessResolver":
        owner_ids = {key.user_id for key in keys}
        scoped_team_ids = {team_id for key in keys for team_id in key.scoped_teams or []}

        member_organization_ids: defaultdict[int, set[str]] = defaultdict(set)
        for user_id, organization_id in OrganizationMembership.objects.filter(user_id__in=owner_ids).values_list(
            "user_id", "organization_id"
        ):
            member_organization_ids[user_id].add(str(organization_id))

        team_organization_ids = {
            team_id: str(organization_id)
            for team_id, organization_id in Team.objects.filter(id__in=scoped_team_ids).values_list(
                "id", "organization_id"
            )
        }

        return cls(
            member_organization_ids={
                user_id: frozenset(organization_ids) for user_id, organization_ids in member_organization_ids.items()
            },
            team_organization_ids=team_organization_ids,
        )

    def resolve(self, key: PersonalAPIKey, organization_id: str) -> PersonalAPIKeyOrganizationAccess:
        member_organization_ids = self._member_organization_ids.get(key.user_id, frozenset())
        organization_ids_in_scope = get_organization_ids_in_key_scope(key, self.team_organization_ids)
        reachable = (
            member_organization_ids
            if organization_ids_in_scope is None
            else organization_ids_in_scope & member_organization_ids
        )
        return PersonalAPIKeyOrganizationAccess(
            has_access_to_organization=organization_id in reachable,
            other_organization_ids=frozenset(reachable - {organization_id}),
        )


class KeyActionOutcome(LabeledStrEnum):
    ROLLED = "rolled"
    DELETED = "deleted"


@frozen
class KeyActionResult:
    outcome: KeyActionOutcome
    owner_id: int
    label: str
    mask_value: str


@frozen
class KeyActionCounts:
    rolled: int
    deleted: int

    @classmethod
    def of(cls, results: Sequence[KeyActionResult]) -> "KeyActionCounts":
        outcomes = Counter(result.outcome for result in results)
        return cls(
            rolled=outcomes[KeyActionOutcome.ROLLED],
            deleted=outcomes[KeyActionOutcome.DELETED],
        )


class BulkKeyActionInterrupted(Exception):
    """A bulk action stopped at a key that raised. Each key commits in its own transaction, so the
    keys in `results` stay changed and their owners still need an email."""

    def __init__(self, results: list[KeyActionResult]) -> None:
        super().__init__(f"Bulk key action stopped after {len(results)} changed keys")
        self.results = results


class OrganizationPersonalAPIKeyActions:
    """Roll and revoke, by an admin of `organization`, of personal API keys that reach it.

    Each action locks the key and checks its organization access again. An action returns `None` when the
    locked key no longer reaches the organization.
    """

    def __init__(self, organization: Organization, acting_user: User) -> None:
        self._organization = organization
        self._organization_id = str(organization.id)
        self._acting_user = acting_user

    def roll(self, key_id: str, owner_id: int) -> KeyActionResult | None:
        with transaction.atomic():
            key = self._lock(key_id, owner_id)
            if key is None:
                return None
            if (
                not PersonalAPIKeyOrganizationAccessResolver.for_keys([key])
                .resolve(key, self._organization_id)
                .has_access_to_organization
            ):
                return None
            with ActingUserContext(self._acting_user), OrganizationAdminKeyActionContext(self._organization_id):
                PersonalAPIKeySerializer(instance=key).roll(key)
            # The roll sets a new mask, which is the one the owner sees in their settings.
            return self._result(key, KeyActionOutcome.ROLLED)

    def revoke(self, key_id: str, owner_id: int) -> KeyActionResult | None:
        with transaction.atomic():
            key = self._lock(key_id, owner_id)
            if key is None:
                return None
            if (
                not PersonalAPIKeyOrganizationAccessResolver.for_keys([key])
                .resolve(key, self._organization_id)
                .has_access_to_organization
            ):
                return None
            result = self._result(key, KeyActionOutcome.DELETED)
            with ActingUserContext(self._acting_user), OrganizationAdminKeyActionContext(self._organization_id):
                key.delete()
            return result

    def roll_all(self) -> tuple[KeyActionCounts, list[KeyActionResult]]:
        return self._act_on_all(self.roll)

    def revoke_all(self) -> tuple[KeyActionCounts, list[KeyActionResult]]:
        return self._act_on_all(self.revoke)

    def _act_on_all(
        self, act: Callable[[str, int], KeyActionResult | None]
    ) -> tuple[KeyActionCounts, list[KeyActionResult]]:
        keys = list(get_organization_personal_api_keys(self._organization).order_by("pk").values_list("id", "user_id"))
        results: list[KeyActionResult] = []
        for key_id, owner_id in keys:
            try:
                result = act(key_id, owner_id)
            except Exception as exc:
                raise BulkKeyActionInterrupted(results) from exc
            if result is not None:
                results.append(result)
        return KeyActionCounts.of(results), results

    @staticmethod
    def _lock(key_id: str, owner_id: int) -> PersonalAPIKey | None:
        # `of=("self",)` locks only the key row, not the owner's user row that `select_related` joins.
        return (
            PersonalAPIKey.objects.select_for_update(of=("self",))
            .select_related("user")
            .filter(pk=key_id, user_id=owner_id)
            .first()
        )

    @staticmethod
    def _result(key: PersonalAPIKey, outcome: KeyActionOutcome) -> KeyActionResult:
        return KeyActionResult(outcome=outcome, owner_id=key.user_id, label=key.label, mask_value=key.mask_value or "")
