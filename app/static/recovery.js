"use strict";

const recoveryCode = document.getElementById("recovery-code");
const copyStatus = document.getElementById("recovery-copy-status");

if (recoveryCode) {
  document.getElementById("copy-recovery-code").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(recoveryCode.textContent.trim());
      copyStatus.textContent = "Herstelcode gekopieerd. Bewaar hem op een veilige plek.";
    } catch {
      copyStatus.textContent = "Kopiëren lukt hier niet. Selecteer de code en kopieer hem handmatig, of download hem.";
    }
  });

  document.getElementById("download-recovery-code").addEventListener("click", () => {
    const content = "Eenmalige herstelcode voor Notitie-app\n\n" +
      recoveryCode.textContent.trim() + "\n\n" +
      "Herstel vereist ook je gebruikersnaam en een actuele 2FA-code.\n" +
      "Bewaar deze code apart van je authenticator.\n";
    const url = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }));
    const download = document.createElement("a");
    download.href = url;
    download.download = "notitie-app-herstelcode.txt";
    document.body.appendChild(download);
    download.click();
    download.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    copyStatus.textContent = "Download gestart. Bewaar het bestand op een veilige plek.";
  });
}
