### Fixed

- `verify-exposure.sh` no longer requires the old placeholder text `Hello World!` on the Svelte sites. naranjo.online now serves its real application, so the live check stopped before probing any port. Tenant identity stays pinned by the exact title, the cross-tenant title refusal and the built-application fallback marker, which a new contract test holds.
