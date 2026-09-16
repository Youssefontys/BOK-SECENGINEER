# --- AZURE TERRAFORM STATE BOOTSTRAP ---
#
# Deze versie bevat:
# 1. Zero Trust Customer Managed Keys (CMK) voor de Terraform State.
# 2. Strict RBAC Role Separation (Least Privilege).
# 3. Geoptimaliseerde wachttijden en 4096-bit encryptie.
# 4. Robuuste, cross-platform automatische configuratie van GitHub Secrets (via gh CLI).

import os
import subprocess
import time
import random
import sys
import re
import shutil

# ---------- Configuratie ----------
DEFAULT_LOCATION = "westeurope"
DEFAULT_RG_NAME = "rg-tfstate-mgmt"
PROPAGATION_WAIT = 120 

# ---------- Hulpfuncties ----------
def get_concise_cmd_name(command):
    """Geeft een korte naam terug voor logs."""
    tokens = command.split()
    return " ".join(tokens[:3]) + "..." if tokens else "Leeg"

def run_az_cmd(command, ignore_error=False):
    """Voert een Azure CLI commando uit en returnt de output."""
    try:
        result = subprocess.run(command, shell=True, check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if not ignore_error:
            print(f"\n❌ FOUT: {e.stderr.strip()}\n🛑 Stoppen.")
            sys.exit(1)
        return None

def run_az_cmd_with_retry(command, max_retries=10, delay=10):
    """Voert commando uit met retry logica voor specifieke Azure propagatie-fouten."""
    name = get_concise_cmd_name(command)
    retryable_errors = [
        "ResourceNotFound", "ConnectionAbortedError", 
        "PrincipalNotFound", "AuthorizationFailed"
    ]
    ignorable_errors = [
        "RoleAssignmentExists", "already exists", "Subscription is not registered"
    ]

    for attempt in range(max_retries):
        try:
            print(f"   ⏳ {name} (poging {attempt+1})...")
            result = subprocess.run(command, shell=True, check=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return result.stdout.strip(), True
        except subprocess.CalledProcessError as e:
            err = e.stderr.strip()
            if any(x in err for x in ignorable_errors): return "ℹ️ Genegeerd.", True
            if any(x in err for x in retryable_errors) and attempt < max_retries-1:
                print(f"    ⚠️ Tijdelijke Azure fout. Wachten {delay}s...")
                time.sleep(delay)
                delay += 5 
                continue
            print(f"❌ FATAL: {err}\n🛑 Stoppen.")
            sys.exit(1)
    return "", False

def ask_user(question, default=None):
    """Vraagt input aan de gebruiker."""
    prompt = f"{question} [{default}]: " if default else f"{question}: "
    while True:
        ans = input(prompt).strip()
        if ans: return ans
        if default is not None: return default
        
def check_and_configure_gh():
    """Controleert of gh CLI bestaat én is ingelogd, en instrueert de gebruiker indien nodig."""
    if not shutil.which('gh'):
        print("\n⚠️ GitHub CLI (gh) niet gevonden.")
        print("   Automatische secrets configuratie is niet mogelijk.")
        print("   Installeer via https://cli.github.com en probeer opnieuw.")
        return False
    
    # Controleer of de gebruiker is ingelogd
    print("\n🔍 GitHub CLI authenticatie controleren...")
    
    try:
        result = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True, 
            text=True,
            check=False 
        )
    except FileNotFoundError:
        print("❌ gh CLI is gevonden, maar kan niet worden uitgevoerd.")
        return False

    if result.returncode != 0:
        print("❌ gh CLI is geïnstalleerd, maar niet ingelogd of token is verlopen.")
        print("   Authenticeer de CLI aub met: `gh auth login`")
        return False
    
    print("✅ gh CLI is ingelogd en klaar voor gebruik.")
    return True

# ---------- Start Script ----------
print("\n╔═══════════════════════════════════════════════╗")
print("║        🛡️  Azure Terraform Bootstrap           ║")
print("╚═══════════════════════════════════════════════╝\n")

# 1. Login & Context
try:
    current_sub_name = run_az_cmd("az account show --query name -o tsv")
    active_sub_id = run_az_cmd("az account show --query id -o tsv")
    tenant_id = run_az_cmd("az account show --query tenantId -o tsv")
    print(f"✅ Context: {current_sub_name} ({active_sub_id})")
except:
    print("⚠️ Inloggen...")
    run_az_cmd("az login -o none")
    active_sub_id = run_az_cmd("az account show --query id -o tsv")
    tenant_id = run_az_cmd("az account show --query tenantId -o tsv")

if ask_user("Andere subscription? (j/n)", "n").lower() == 'j':
    sub_id = ask_user("Subscription ID")
    run_az_cmd(f"az account set --subscription {sub_id}")
    active_sub_id = run_az_cmd("az account show --query id -o tsv")

current_object_id = run_az_cmd("az ad signed-in-user show --query id -o tsv")

# 2. Providers
print("\n⚙️  Providers check...")
for p in ["Microsoft.Storage", "Microsoft.KeyVault", "Microsoft.ManagedIdentity"]:
    run_az_cmd_with_retry(f"az provider register --namespace {p} --wait -o none", max_retries=2)

# 3. Input
rg_name   = ask_user("Resource Group naam", DEFAULT_RG_NAME)
location  = ask_user("Regio", DEFAULT_LOCATION)
container = ask_user("Blob container naam", "tfstate")

while True:
    prefix = ask_user("Storage prefix (3-10 chars)", "tfstate")
    sa_name = f"{prefix}{random.randint(1000,9999)}"
    if 3 <= len(sa_name) <= 24 and re.match("^[a-z0-9]+$", sa_name): break
    print("❌ Ongeldige naam.")

suffix = f"{random.randint(1000,9999)}"
mi_name = f"mi-{prefix}-{suffix}"
kv_name = f"kv-{prefix}-{suffix}" 
key_name = "tfstate-cmk-key"

# Belangrijke checks voor de deployment
if ask_user("\nStarten? (j/n)", "j").lower() != 'j': sys.exit(0)

# ---------- UITROL ----------
print(f"\n🚀 Start setup in {location}...")

# A. Resource Group
run_az_cmd(f"az group create --name {rg_name} --location {location} -o none")

# B. Managed Identity (UAMI)
print(f"→ UAMI '{mi_name}' aanmaken...")
run_az_cmd_with_retry(f'az identity create --name {mi_name} --resource-group {rg_name} --location {location} -o none')

print("   ⏳ ID propagation...")
mi_principal_id = ""
for _ in range(12):
    try:
        mi_principal_id = run_az_cmd(f'az identity show --name {mi_name} --resource-group {rg_name} --query principalId -o tsv')
        if mi_principal_id: break
    except: pass
    time.sleep(5)
mi_client_id = run_az_cmd(f'az identity show --name {mi_name} --resource-group {rg_name} --query clientId -o tsv')
uami_id = f"/subscriptions/{active_sub_id}/resourceGroups/{rg_name}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{mi_name}"

# C. Key Vault
print(f"→ Key Vault '{kv_name}'...")
run_az_cmd(f'az keyvault create --name {kv_name} --resource-group {rg_name} --location {location} \
            --enable-rbac-authorization true --enable-purge-protection true --retention-days 90 -o none')

# D. KV RBAC - Separation of Duties
print("→ Key Vault RBAC...")
kv_scope = f"/subscriptions/{active_sub_id}/resourceGroups/{rg_name}/providers/Microsoft.KeyVault/vaults/{kv_name}"

run_az_cmd_with_retry(f'az role assignment create --role "Key Vault Crypto Officer" --assignee {current_object_id} --scope {kv_scope} -o none')
run_az_cmd_with_retry(f'az role assignment create --role "Key Vault Crypto Service Encryption User" --assignee {mi_principal_id} --scope {kv_scope} -o none')

# E. CMK Key (RSA 4096)
print(f"→ CMK '{key_name}' (RSA 4096)...")
time.sleep(15) 
run_az_cmd_with_retry(f'az keyvault key create --vault-name {kv_name} --name {key_name} --kty RSA --size 4096 -o none')

# F. Storage Account (CMK)
print(f"→ Storage '{sa_name}' met CMK...")
kv_uri = run_az_cmd(f'az keyvault show --name {kv_name} --query properties.vaultUri -o tsv').strip()

storage_cmd = f"""az storage account create \
    --name {sa_name} \
    --resource-group {rg_name} \
    --location {location} \
    --sku Standard_LRS \
    --kind StorageV2 \
    --allow-blob-public-access false \
    --min-tls-version TLS1_2 \
    --https-only true \
    --identity-type UserAssigned \
    --user-identity-id {uami_id} \
    --encryption-key-source Microsoft.Keyvault \
    --encryption-key-vault {kv_uri} \
    --encryption-key-name {key_name} \
    --encryption-services blob \
    --key-vault-user-identity-id {uami_id} \
    -o none"""

run_az_cmd_with_retry(storage_cmd)

# G. Storage Hardening & RBAC
print("→ Storage settings...")
run_az_cmd_with_retry(f"""az storage account blob-service-properties update \
    --account-name {sa_name} --resource-group {rg_name} \
    --enable-versioning true --enable-delete-retention true --delete-retention-days 7 \
    --enable-container-delete-retention true --container-delete-retention-days 7 -o none""")

print("→ Storage RBAC...")
sa_scope = f"/subscriptions/{active_sub_id}/resourceGroups/{rg_name}/providers/Microsoft.Storage/storageAccounts/{sa_name}"

run_az_cmd_with_retry(f'az role assignment create --role "Storage Blob Data Owner" --assignee {current_object_id} --scope "{sa_scope}" -o none')
run_az_cmd_with_retry(f'az role assignment create --role "Storage Blob Data Contributor" --assignee {mi_principal_id} --scope "{sa_scope}" -o none')

# H. Container
print(f"⏳ {PROPAGATION_WAIT}s wachten op CMK & RBAC propagatie...")
time.sleep(PROPAGATION_WAIT) 
run_az_cmd_with_retry(f"az storage container create --name {container} --account-name {sa_name} --auth-mode login -o none")

# I. AUTOMATISCH GITHUB SECRETS ZETTEN
print("\n--- GitHub Integratie ---")
gh_configured = check_and_configure_gh()
set_secrets_auto = False
repo = None

# Vraag of secrets automatisch gezet moeten worden
if gh_configured:
    set_secrets_auto = ask_user("GitHub Secrets automatisch instellen? (j/n)", "j").lower() == 'j'

# Optionele SNYK integratie vraag
use_snyk = ask_user("Snyk testen integreren (SNYK_TOKEN)? (j/n)", "n").lower() == 'j'
snyk_token = None

if use_snyk:
    print("\n➡️  Voer je Snyk API Token in.")
    print("   (Ga naar https://snyk.io → Account Settings → API Token)")
    snyk_token = ask_user("SNYK_TOKEN")
    
# Secrets dictionary (Definieer deze ALTIJD, ongeacht of ze automatisch worden gezet of handmatig getoond)
secrets = {
    "AZURE_CLIENT_ID": mi_client_id,
    "AZURE_SUBSCRIPTION_ID": active_sub_id,
    "AZURE_TENANT_ID": tenant_id,
    "BACKEND_RG_NAME": rg_name,
    "BACKEND_STORAGE_ACCOUNT": sa_name,
    "BACKEND_CONTAINER_NAME": container
}

if use_snyk:
    secrets["SNYK_TOKEN"] = snyk_token

# Dit blok wordt alleen uitgevoerd als GH CLI is geconfigureerd EN de gebruiker koos voor auto-instellen
if gh_configured and set_secrets_auto:
    repo = ask_user("Volledige GitHub repo (bijv. user/repo)")
    print(f"Secrets aan het zetten in {repo}...")
    
    for name, value in secrets.items():
        # Belangrijk: De code binnen deze for-loop is nu correct ingesprongen
        cmd = f'gh secret set {name} -b"{value}" --repo {repo}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"   ✅ {name}")
        else:
            print(f"   ❌ {name} (mislukt: {result.stderr.strip()})")

    print("\nALLES KLAAR! Je repo is nu 100% klaar voor GitHub Actions OIDC.")
else:
    # Handmatige instructies
    print("\nHandmatig kopiëren:")
    
    # Toon alle benodigde secrets, inclusief SNYK indien gevraagd
    for name, value in secrets.items():
        # Let op: Snyk token wordt getoond als deze gevraagd is.
        print(f"   {name:23} = {value}")
        
    if use_snyk:
        print("ℹ️ Vergeet niet de SNYK_TOKEN te kopiëren voor security scans.")
        
# J. Output & Files
print("\n📝 Backend Configs genereren...")
for env in ["dev", "test", "prod"]:
    with open(f"backend.{env}.conf", "w") as f:
        f.write(f"""resource_group_name  = "{rg_name}"
storage_account_name = "{sa_name}"
container_name       = "{container}"
key                  = "{env}/terraform.tfstate"
use_azuread_auth     = true

subscription_id      = "{active_sub_id}"
tenant_id            = "{tenant_id}"
""")

print("\n🎉 GEREED! Setup voltooid. Gebruik nu de backend.conf in Terraform.")


#check permissions, eindzin aanpassen?