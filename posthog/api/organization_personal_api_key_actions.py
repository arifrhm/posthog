from collections import defaultdict
from collections.abc import Mapping, Sequence

from django.db import transaction

from posthog.api.personal_api_key import PersonalAPIKeySerializer
from posthog.dataclasses import frozen
from posthog.enums import LabeledStrEnum
from posthog.models import Organization, OrganizationMembership, Team, User
from posthog.models.activity_logging.model_activity import ActingUserContext
from posthog.models.activity_logging.personal_api_key_utils import OrganizationAdminKeyActionContext
from posthog.models.personal_api_key import PersonalAPIKey


@frozen
class PersonalAPIKeyOrganizationAccess:
    has_access_to_organization: bool
    other_organization_ids: frozenset[str]


class PersonalAPIKeyOrganizationAccessResolver:
    """Organization access follows `posthog/permissions.py`, which applies each non-empty `scoped_teams` and
    `scoped_organizations` list as its own limit. An organization the owner left never counts."""

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
        live = self._member_organization_ids.get(key.user_id, frozenset())
        team_org = self.team_organization_ids
        teams, orgs = key.scoped_teams or [], key.scoped_organizations or []
        if teams:
            reachable = {
                team_org[t]
                for t in teams
                if t in team_org and team_org[t] in live and (not orgs or team_org[t] in orgs)
            }
        elif orgs:
            reachable = set(orgs) & live
        else:
            reachable = set(live)
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
            result = self._result(key, KeyActionOutcome.ROLLED)
            with ActingUserContext(self._acting_user), OrganizationAdminKeyActionContext(self._organization_id):
                PersonalAPIKeySerializer(instance=key).roll(key)
            return result

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
