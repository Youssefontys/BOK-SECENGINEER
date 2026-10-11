# Vault voor lokale ontwikkeling en CI

Start vanuit de repositoryroot met `docker compose up -d --build`, na het invullen
van de vier secrets in `.env` volgens `.env.example`. Een handmatig `VAULT_TOKEN`
is niet nodig. Deze configuratie is uitsluitend voor ontwikkeling en CI.

- `vault` gebruikt file-storage in `vaultdata`; encryptiesleutels blijven behouden
  na een containerherstart. Er is geen hostpoort voor Vault.
- `vault-init` initialiseert en unsealt Vault, activeert Transit, maakt de
  `aes256-gcm96`-sleutel `notes` en een beperkt token. De service blijft draaien om
  Vault na een herstart te unsealen en het periodieke token te vernieuwen.
- Het root-token en de unseal-key staan alleen in `vaultbootstrap`. De app krijgt
  alleen het beperkte token uit `vaulttoken`, via een read-only mount.
- `db-migrate` voegt idempotent de kolom `notes.encrypted` toe, ook bij bestaande
  databasevolumes. De applicatierol krijgt hierdoor geen DDL-rechten.
- Voor het starten van de webserver zet `flask --app app encrypt-notes` bestaande
  plaintext-notities transactioneel om. Nieuwe en aangepaste notities slaan
  zowel titel als inhoud als Vault-ciphertext op. De flag onderscheidt bestaande
  plaintext van ciphertext, ook als iemand letterlijk `vault:v1:...` schreef.
- Bij een Vault-fout worden wijzigingen niet als plaintext opgeslagen. De app
  geeft een generieke 503-reactie bij routeverzoeken.
- TOTP-secrets gebruiken voorlopig nog `pgcrypto` en `DB_ENCRYPTION_KEY`.

Controleer configuratie en draai de tests:

```sh
docker compose config --quiet
docker compose exec -T app pip install --user -r requirements-dev.txt
docker compose exec -T app python -m pytest tests -v
```

Bewaar `dbdata`, `vaultdata` en `vaultbootstrap` samen. `docker compose down`
behoudt volumes; `docker compose down -v` verwijdert de database én Vault-sleutels.
Verlies van Vault-sleutels maakt bestaande ciphertext onleesbaar. Een ontbrekende
bootstrap-state bij een bestaande Vault stopt de bootstrap; hij maakt geen nieuwe
sleutel om dit te omzeilen.

De bootstrap gebruikt één lokaal bewaarde unseal-key, HTTP op het containernetwerk
en een lokaal bewaard root-token. De tokenfile is leesbaar voor de non-root app,
maar alleen de bootstrap-service kan deze via het volume schrijven. Deze aanpak
beschermt niet tegen een beheerder van de Docker-host. Voor productie zijn TLS,
afzonderlijk beheerde unseal-secrets en workload-authenticatie noodzakelijk.

Lokaal geverifieerd: 27 unit/routetests, Compose-validatie en een echte Vault-server
voor encryptie/decryptie, beperkte tokenrechten, herstart en tokenvervanging. De
complete Docker/PostgreSQL-stack is hier niet uitgevoerd; de integratie- en
herstarttests staan in de CI-workflow.

Zie [Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit),
[tokenbeheer](https://developer.hashicorp.com/vault/api-docs/auth/token) en
[file-storage](https://developer.hashicorp.com/vault/docs/configuration/storage/filesystem).
