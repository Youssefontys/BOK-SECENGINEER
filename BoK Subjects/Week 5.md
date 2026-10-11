# Week 5 — Authentication

Onderstaande bevindingen zijn gebaseerd op de code in `app/` en de lokale Compose/Vault-integratie. De Azure-infrastructuur en de actieve deployment zijn hiervoor niet gecontroleerd.

### User authentication: wachtwoord + MFA

De applicatie implementeert zelf gebruikersauthenticatie, zonder externe identity provider:

1. Bij registratie wordt een wachtwoord van minimaal 12 tekens vereist. Alleen de Argon2id-hash met automatisch gegenereerde salt wordt opgeslagen; het wachtwoord zelf niet.
2. Na controle van gebruikersnaam en wachtwoord krijgt de sessie alleen een `pending_user_id`. Daarmee heeft de gebruiker nog geen toegang tot notities.
3. De gebruiker voert een TOTP-code uit een authenticator-app in. Alleen na succesvolle verificatie wordt de sessie gewist en een `user_id` ingesteld. Dit combineert een kennisfactor (wachtwoord) en een bezitsfactor (het TOTP-geheim in de authenticator).

**Securityvoordeel:** een gestolen wachtwoord alleen is onvoldoende om in te loggen. Argon2id maakt offline wachtwoordaanvallen duurder; unieke salts voorkomen dat identieke wachtwoorden dezelfde hash krijgen. Notities lezen, aanmaken, aanpassen en verwijderen vereist een volledig geauthenticeerde sessie.

**Beveiliging van de authenticatie:**

- TOTP-geheimen worden willekeurig gegenereerd met `pyotp.random_base32()` en bij registratie getoond als secret en QR-code. In de database worden ze versleuteld opgeslagen met `pgcrypto`; verificatie gebruikt het ontsleutelde geheim. De sleutel komt uit `DB_ENCRYPTION_KEY`.
- TOTP-verificatie accepteert het huidige interval van 30 seconden en het vorige en volgende interval om klokverschillen op te vangen.
- Flask ondertekent sessiecookies met `FLASK_SECRET_KEY` uit de omgeving. De cookie-inhoud is niet versleuteld. `HttpOnly` beperkt toegang vanuit JavaScript, `Secure` is standaard ingeschakeld en `SameSite=Lax` beperkt het meesturen bij cross-site verzoeken. `COOKIE_SECURE=false` is alleen bedoeld voor lokale HTTP-tests.
- De sessie wordt gewist na de wachtwoordstap, na succesvolle MFA en bij uitloggen. Een fout wachtwoord en een onbekende gebruikersnaam geven dezelfde foutmelding.
- SQL-queries gebruiken parameters. Notitiequeries filteren op `user_id`, zodat een geauthenticeerde gebruiker alleen eigen notities kan benaderen. Dit is autorisatie, aanvullend op authenticatie.

TOTP-verificatie bewaart het laatst gebruikte tijdsinterval in de database en accepteert het niet opnieuw. De pending MFA-stap vervalt na tien minuten. Authenticatie- en herstelformulieren hebben CSRF-tokens. Een sessieversie wordt bij iedere geauthenticeerde aanvraag gecontroleerd, zodat wachtwoordherstel bestaande sessies en pending logins ongeldig maakt.

**Nog ontbrekend:** rate limiting/account lockout voor gewone login en login/2FA, en CSRF-tokens voor notitiemutaties en uitloggen. De registratie bevestigt nog niet dat de authenticator succesvol is ingesteld. TOTP is niet phishingbestendig. Ook kan de snellere afhandeling van onbekende gebruikersnamen accounts via timing verklappen. De encryptiesleutel voor TOTP wordt aan PostgreSQL doorgegeven; externe secretopslag en sleutelrotatie hiervoor zijn nog niet geïmplementeerd. Deze implementatie is daarom een concept en geen volledig geharde authenticatielaag.

### Wachtwoordherstel

Herstel via `/recover` vereist **gebruikersnaam + eenmalige herstelcode + actuele 2FA-code**, plus een nieuw wachtwoord dat tweemaal wordt ingevoerd. Alleen een gestolen herstelcode is dus onvoldoende. Na herstel moet de gebruiker opnieuw inloggen met het nieuwe wachtwoord en een nieuwe authenticator-code.

- Bij registratie wordt een willekeurige herstelcode van 192 bits eenmaal getoond naast de 2FA-QR-code. Kopiëren/downloaden gebeurt lokaal in de browser. De database bewaart alleen een Argon2id-hash; cookies en URLs bevatten de herstelcode niet.
- Herstelcode en TOTP worden samen met de wachtwoordwijziging transactioneel verbruikt. Een row lock voorkomt dat twee gelijktijdige herstelverzoeken dezelfde code gebruiken.
- Poginglimieten staan in PostgreSQL en gelden over workers heen: maximaal vijf herstelpogingen per account en twintig per client-IP, per vijftien minuten. Verkeerde bewijzen geven dezelfde foutmelding.
- Herstel verhoogt de sessieversie. Oude sessies en eerder begonnen logins verliezen toegang. Geheime pagina's worden met `Cache-Control: no-store` verstuurd.
- Bestaande gebruikers maken een herstelcode aan via **Herstelcode beheren**, met hun huidige wachtwoord en een verse 2FA-code. Aanmaken vervangt een eerdere code. Na gebruik kan daar een nieuwe code worden aangemaakt.
- Bewaar de code offline of in een wachtwoordmanager, apart van de authenticator. Zonder herstelcode of authenticator is deze zelfservice-route niet beschikbaar; er is geen bypass.

De IP-limiet gebruikt het directe clientadres. Achter een proxy moet de vertrouwde proxyconfiguratie apart worden ingericht; ongecontroleerde forwarding-headers worden niet vertrouwd.

### System authentication: databaseaccount en Vault-token

Binnen `app/` is systeemauthenticatie aanwezig in de vorm van een PostgreSQL-account met wachtwoord: `roles.sh` maakt een applicatierol met `LOGIN PASSWORD`, en de applicatie verbindt via `psycopg.connect(DATABASE_URL)`. De connectiestring komt uit de omgeving. Welk account de deployment daadwerkelijk gebruikt en welke PostgreSQL-authenticatiemethode is ingesteld, is hiermee niet vastgesteld.

**Securityvoordeel en beveiliging:** het databaseaccount identificeert de applicatie bij de database. De bijbehorende autorisatie volgt least privilege: de rol krijgt toegang tot het schema, CRUD-rechten op `users` en `notes` en benodigde sequencerechten, maar geen eigenaarschap of rechten om tabellen aan te maken. Dit beperkt de impact van misbruik van het applicatieaccount. Het wachtwoord en de connectiestring moeten als secrets worden beheerd; de code haalt de connectiestring uit de omgeving.

Daarnaast authenticeert de app zich bij **HashiCorp Vault** met een servicetoken in de `X-Vault-Token`-header. De lokale bootstrap-service maakt een afzonderlijk, periodiek token met alleen `update` op `transit/encrypt/notes` en `transit/decrypt/notes`. Het token wordt vernieuwd en via een read-only volume aan de non-root app beschikbaar gesteld. De app leest het tokenbestand opnieuw bij iedere aanvraag, zodat tokenvervanging geen app-restart vereist. De app krijgt geen root-token, unseal-key of encryptiesleutel, en mag geen sleutels uitlezen, roteren of engines beheren.

**Securityvoordeel:** een databaselek onthult bij nieuwe of gemigreerde notities alleen ciphertext voor titel en inhoud. Encryptie en decryptie gebeuren in Vault Transit; de AES-256-GCM-sleutel verlaat Vault niet. Misbruik van het applicatietoken blijft beperkt tot encryptie/decryptie met de notitiesleutel. Het token kan nog steeds alle ciphertext onder die sleutel ontsleutelen; eigendomscontrole gebeurt in de app.

**Beperkingen van de lokale/CI-opzet:** Vault heeft geen hostpoort, maar gebruikt HTTP binnen het Compose-netwerk. Root-token en unseal-key staan in een afzonderlijk bootstrap-volume voor automatisch unsealen; de app kan dit volume niet lezen. Dit is ontwikkelgemak en geen productiegeschikte secretscheiding bij toegang tot de Docker-host. Productie vereist TLS, apart beheerde unseal-secrets en workload-authenticatie/tokenbeheer. De TOTP-geheimen blijven voorlopig via PostgreSQL `pgcrypto` beveiligd.

**Niet geïmplementeerd in deze app-opzet:** clientcertificaten, mTLS, OAuth/OIDC of managed identity. De app dwingt ook geen TLS-modus of certificaatcontrole voor de databaseverbinding af; dat hangt af van `DATABASE_URL` en de serverconfiguratie. `Secure` op sessiecookies regelt cookievervoer en bewijst geen systeemauthenticatie of HTTPS-configuratie van de deployment.

### Notities aanpassen

Naast aanmaken en verwijderen kunnen gebruikers via **Aanpassen** de titel en inhoud van eigen notities wijzigen. `GET /notes/<id>/edit` toont de bestaande inhoud; `POST` valideert en slaat wijzigingen op. Zowel de leesquery als de update controleert `id` én `user_id`. Een ontbrekende notitie of een notitie van een ander geeft dezelfde 404-reactie. De invoerregels zijn gelijk aan die bij aanmaken; bij een validatiefout blijft de ingevoerde tekst behouden. Jinja escaping en de bestaande CSP beschermen de weergave tegen scriptinjectie. CSRF-bescherming blijft een open punt voor alle mutaties.

Bronnen: `app/app.py`, `app/vault_crypto.py`, `app/schema.sql`, `app/roles.sh`, `app/templates/`, `compose.yaml` en `scripts/vault_init.py`. Achtergrond: [Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit) en [Vault-tokenbeheer](https://developer.hashicorp.com/vault/api-docs/auth/token).

Verificatie: de bewerkroute, Vault-client en bestaande securityheaders zijn lokaal getest met `python -m pytest app/tests/test_edit_note.py app/tests/test_vault_crypto.py app/tests/test_securityheaders.py -q` (27 tests geslaagd). Deze tests gebruiken doubles voor externe systemen. De aanvullende tests in `app/tests/test_autorisatie.py` en `app/tests/test_vault_integration.py` gebruiken PostgreSQL en Vault en worden door CI uitgevoerd. Voor lokale integratietests moet de Compose-stack draaien. De complete Docker-stack is in deze Windows-omgeving niet uitgevoerd; Docker is hier niet beschikbaar.

Aanvullend is de Compose-configuratie succesvol gecontroleerd met Docker Compose 2.39.2. Met een echte Vault 1.21.0-server zijn bootstrap, encryptie/decryptie, weigering van beheerrechten, sleutelbehoud na herstart en vervanging van een ingetrokken applicatietoken getest. De CI-workflow bevat ook een herstartcontrole voor bestaande ciphertext.
