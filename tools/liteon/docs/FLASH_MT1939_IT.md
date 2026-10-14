# ASUS BW-12B1LT 1.03 MT1939: aggiornamento diretto

Il pacchetto `dist/bw12b1lt-mt1939-watchdog-fix.zip` applica direttamente il nuovo firmware:
SHA-256 `db7979b10529b30732935dea22f12b4560f63316fc8da6fd6dac5eb3b951e413`.
La nuova correzione inizializza contatore e timestamp nativi prima di ogni
C0 DVD/BD valido e non vuoto. Evita che il watchdog READ(12) utilizzi un
timestamp vecchio e produca subito `03/11/05`. Restano le due preparazioni
precedenti. Analisi e limiti: [MT1939_WII_WATCHDOG_IT.md](MT1939_WII_WATCHDOG_IT.md).
È un candidato sperimentale: la risoluzione del bug Wii va verificata sul drive.
Il flag `apply --force-source` accetta una sorgente compatibile con hash completo
diverso dall'originale. Non cambia la destinazione e non è un flasher universale.

Restano obbligatori identità ASUS BW-12B1LT 1.03, INQUIRY/sessione/protocollo
attesi, due backup completi identici e confronto completo tra flash live e
backup prima di qualsiasi comando di aggiornamento. I settori di boot, la
finestra autenticata, le code riservate e tre regioni del codice nativo di
aggiornamento devono avere gli hash fissati nel runner. Un'altra destinazione,
un backup incoerente o una sorgente incompatibile vengono rifiutati.
Senza `--force-source`, `apply` continua a richiedere l'originale esatto.
`rollback` continua a richiedere il nuovo candidato esatto.

Le transizioni dai candidati `5eac461d…`, `56432d9b…` e `535510d8…` sono controllate
con il loader/programmatore nativo emulato su NOR c22015 e c22415.
Questo candidato richiede ancora una prova fisica.

Usare Linux e Python 3 standard. Rimuovere il disco e chiudere redumper e altre
applicazioni che usano il drive. Eseguire i blocchi separatamente e fermarsi
al primo errore. Tutti gli output devono essere nuovi.

## 1. Estrarre e controllare

```sh
unzip bw12b1lt-mt1939-watchdog-fix.zip
cd bw12b1lt-mt1939-watchdog-fix
sha256sum -c SHA256SUMS
mkdir -p state
```

## 2. Acquisire due letture del firmware installato

```sh
sudo python3 current/tools/liteon/device/read_flash.py /dev/sr0 \
  --dump --output state/before-update
```

Il runner controlla questo backup e le regioni compatibili prima di aprire
il dispositivo per l'aggiornamento. Non sostituirlo con un'immagine sintetica.

## 3. Applicare direttamente il nuovo firmware

Questo comando scrive la flash una volta, senza ripristino intermedio:

```sh
sudo python3 current/tools/liteon/device/native_trial.py apply \
  --force-source \
  --package current/dump/bw12b1lt-native-watchdog-fix-package \
  --baseline state/before-update \
  --device /dev/sr0 --output state/direct-update
```

Il controllo completo live deve corrispondere al backup. I 512 blocchi
caricati in RAM vengono confrontati prima della finalizzazione, inviata una
sola volta. Boot e code riservate sono preservati.

Solo dopo uscita riuscita e risultato
`transport_accepted_requires_cold_readback`, togliere completamente
alimentazione al drive e riaccenderlo.
Se la finalizzazione fallisce, va in timeout o viene interrotta, mantenere
l'alimentazione, conservare `state` e non ripetere la scrittura: l'esito
potrebbe essere incerto. Un'interruzione della programmazione può rendere il
drive inutilizzabile, anche se il boot è preservato.

## 4. Verificare tutta la nuova flash dopo la riaccensione

```sh
sudo python3 current/tools/liteon/device/read_flash.py /dev/sr0 \
  --dump --output state/after-update &&
python3 current/tools/liteon/device/native_trial.py verify-readback \
  --state candidate --baseline state/after-update
```

Richiedere `full_image_matches_expected: true` e uscita riuscita.
L'accettazione del trasporto da sola non certifica la programmazione fisica.
Conservare tutta la directory `state`.

Per verificare la correzione ottica, dopo una nuova accensione provare C0
senza `--prime-native-read` e redumper MT1939_MINIMAL senza preparazione READ(10)
automatica, ripetendo dopo Ctrl+C. Il redumper con workaround rimane usabile,
ma potrebbe nascondere un difetto residuo nella preparazione del firmware.

Il pacchetto include anche il probe di sola lettura. Dopo aver tolto e
ripristinato alimentazione, inserire il Wii ed eseguire prima di altri dump:

```sh
sudo python3 diagnostics/mt1939_receive_probe.py /dev/sr0 \
  --output state/wii-watchdog-fix-01
cat state/wii-watchdog-fix-01/report.json
```

Ripetere il probe in una directory nuova anche dopo alcuni secondi di inattività,
senza READ(10) preliminare. La firma INQUIRY resta 1.0.4: il readback completo
è necessario per distinguere questo candidato dai precedenti.

Questo comando prova i quattro flag C0 senza READ(10) preliminare. Controllare
`complete: true` nelle letture raw; il successivo dump completo in redumper
deve confermare anche l'assenza di errori EDC. I flag di descrambling nativo
sono diagnostici e non convalidano da soli i dati Nintendo.

## Ripristino successivo

Per tornare all'originale da un nuovo candidato verificato e rispondente:

```sh
sudo python3 current/tools/liteon/device/native_trial.py rollback \
  --package current/dump/bw12b1lt-native-watchdog-fix-package \
  --baseline state/after-update --device /dev/sr0 --output state/rollback-new
```

Dopo accettazione e uscita riuscita, togliere e ripristinare l'alimentazione,
acquisire un nuovo dump in `state/restored` e verificarlo con
`verify-readback --state original --baseline state/restored`.
Questo rollback torna all'originale, non al vecchio candidato patchato.
