import posthog from 'posthog-js'

import { LemonDialog } from '@posthog/lemon-ui'

import type { OrganizationPersonalAPIKeyApi } from 'products/platform_features/frontend/generated/api.schemas'

import type { KeyAction, KeyActionTarget } from './organizationPersonalAPIKeysLogic'

function captureDialogOpened(action: KeyAction, target: KeyActionTarget): void {
    posthog.capture('organization personal api key action dialog opened', { action, target })
}

function keyName(key: OrganizationPersonalAPIKeyApi, owner: string): JSX.Element {
    return (
        <>
            The key <span className="font-mono">{key.mask_value}</span> owned by <strong>{owner}</strong>
        </>
    )
}

export function openRollKeyDialog(key: OrganizationPersonalAPIKeyApi, owner: string, onConfirm: () => void): void {
    captureDialogOpened('roll', 'single')
    LemonDialog.open({
        maxWidth: 480,
        title: 'Roll personal API key?',
        description: (
            <>
                <p>
                    {keyName(key, owner)} gets a new secret that is not shown to anyone. It keeps its scopes and
                    settings, but stops working until the owner rolls it again in their own settings.
                </p>
                {key.reaches_other_organizations ? (
                    <p>This key also works in other organizations, so it stops working there too.</p>
                ) : null}
                <p>The owner gets an email about this change.</p>
            </>
        ),
        primaryButton: {
            children: 'Roll key',
            status: 'danger',
            onClick: onConfirm,
            'data-attr': 'organization-personal-api-key-roll-confirm',
        },
        secondaryButton: { children: 'Cancel' },
    })
}

export function openRevokeKeyDialog(key: OrganizationPersonalAPIKeyApi, owner: string, onConfirm: () => void): void {
    captureDialogOpened('revoke', 'single')
    LemonDialog.open({
        maxWidth: 480,
        title: 'Revoke personal API key?',
        description: (
            <>
                {key.reaches_other_organizations ? (
                    <p>
                        {keyName(key, owner)} also works in other organizations. Revoking it removes its access to this
                        organization and gives it a new secret that is not shown to anyone. It keeps its access to the
                        other organizations, but stops working there until the owner rolls it again in their own
                        settings.
                    </p>
                ) : (
                    <p>
                        {keyName(key, owner)} works only in this organization, so revoking it deletes the key. Anything
                        that uses it stops working until the owner creates a new key.
                    </p>
                )}
                <p>To stop the current value but keep the key's name and scopes, roll the key instead.</p>
                <p>The owner gets an email about this change.</p>
            </>
        ),
        primaryButton: {
            children: 'Revoke key',
            status: 'danger',
            onClick: onConfirm,
            'data-attr': 'organization-personal-api-key-revoke-confirm',
        },
        secondaryButton: { children: 'Cancel' },
    })
}
