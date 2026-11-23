# ASUS BW-12B1LT 1.03 MT1939: aggiornamento diretto

Candidato attuale: OmniDrive 1.0.4 con rilevamento XGD (Xbox 360), SHA-256
`e96917094cd65dfc0ef632b6a5162fe9bb1ddd949b7122a5ad92ff529a00aab7`.
Comprende le correzioni watchdog e di preparazione della lettura
([MT1939_WII_WATCHDOG_IT.md](MT1939_WII_WATCHDOG_IT.md)) e la lettura del
security sector rinviata alla prima READ CAPACITY DVD
([MT1939_XGD_IT.md](MT1939_XGD_IT.md)). Contiene ancora una traccia
diagnostica temporanea. Verificato fisicamente con un disco XGD2; gli altri
supporti vanno ancora provati.
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

Le transizioni dai candidati precedenti al nuovo sono controllate con il
loader/programmatore nativo emulato su NOR c22015 e c22415
(`tests/test_liteon_native_trial.py`). Il flash di questo candidato da
`99e7ac42…` e `aa9fac8e…` è riuscito fisicamente con readback completo.

Usare Linux e Python 3 standard. Rimuovere il disco e chiudere redumper e altre
applicazioni che usano il drive. Eseguire i blocchi separatamente e fermarsi
al primo errore. Tutti gli output devono essere nuovi.

## 1. Generare il pacchetto (offline)

Servono ARM GCC, armips, CMake/Ninja, Python 3 con `pycryptodome`, `pefile`,
`unicorn`, `capstone` e `numpy`, il firmware originale in `firmware/`, la
C0deKing Flash Utility 7.2.0 (`Flash_Utility.exe`, SHA-256
`34dd3c6a…f9f3`, vedi [../README.md](../README.md)) e, in `dump/`, il baseline
e il pacchetto di ripristino dell'originale. Le prove si generano sempre
dall'originale, non dal firmware installato.

```sh
mkdir -p build && (cd build && cmake -G Ninja .. && ninja ASUS_BW_12B1LT_1_03)
python3 tools/liteon/patch_verify/verify_native_port.py firmware/ASUS_BW-12B1LT_1.03.bin \
  --generated patched_firmware/ASUS_BW-12B1LT_1.03_OmniDrive-1.0.4.bin \
  --utility Flash_Utility.exe --capture dump/bw12b1lt-native-original-baseline/report.json \
  --output dump/mt1939-xgd-evidence.json
python3 tools/liteon/device/native_trial.py prepare \
  --original-package dump/bw12b1lt-original-restore-package \
  --original firmware/ASUS_BW-12B1LT_1.03.bin \
  --patched patched_firmware/ASUS_BW-12B1LT_1.03_OmniDrive-1.0.4.bin \
  --baseline dump/bw12b1lt-native-original-baseline \
  --evidence dump/mt1939-xgd-evidence.json --output dump/bw12b1lt-native-xgd-package
python3 tools/liteon/device/native_trial.py inspect \
  --package dump/bw12b1lt-native-xgd-package --baseline dump/bw12b1lt-native-original-baseline
mkdir -p state
```

Senza il pacchetto di ripristino, `prepare --utility Flash_Utility.exe` ricava
profilo, staging e tag dell'originale direttamente con l'encoder dell'utility.
Il build deve dare esattamente l'hash indicato sopra, altrimenti `prepare`
rifiuta l'immagine.

## 2. Acquisire due letture del firmware installato

```sh
sudo python3 tools/liteon/device/read_flash.py /dev/sr0 \
  --dump --output state/before-update
```

Il runner controlla questo backup e le regioni compatibili prima di aprire
il dispositivo per l'aggiornamento. Non sostituirlo con un'immagine sintetica.

## 3. Applicare direttamente il nuovo firmware

Questo comando scrive la flash una volta, senza ripristino intermedio:

```sh
sudo python3 tools/liteon/device/native_trial.py apply \
  --force-source \
  --package dump/bw12b1lt-native-xgd-package \
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
sudo python3 tools/liteon/device/read_flash.py /dev/sr0 \
  --dump --output state/after-update &&
python3 tools/liteon/device/native_trial.py verify-readback \
  --state candidate --baseline state/after-update
```

Richiedere `full_image_matches_expected: true` e uscita riuscita.
L'accettazione del trasporto da sola non certifica la programmazione fisica.
Conservare tutta la directory `state`.

Per verificare il rilevamento XGD, spegnere e riaccendere il drive con un
disco Xbox 360 inserito e avviare redumper: alla prima READ CAPACITY il drive
legge il security sector e la capacità include la partizione di gioco
(Skate 2: 3825924 invece di 2724). Redumper deve riportare
`omnidrive: XGD detected`. Per controllare lo stato in RAM con `F1 02`
(settore copiato, `layer0End`, `lastSector`, traccia per tentativo) vedere la
sezione diagnostica di [MT1939_XGD_IT.md](MT1939_XGD_IT.md).

Le prove Wii del candidato watchdog sono descritte in
[MT1939_WII_WATCHDOG_IT.md](MT1939_WII_WATCHDOG_IT.md). La firma INQUIRY resta
1.0.4: il readback completo è necessario per distinguere i candidati.

## Ripristino successivo

Per tornare all'originale da un nuovo candidato verificato e rispondente:

```sh
sudo python3 tools/liteon/device/native_trial.py rollback \
  --package dump/bw12b1lt-native-xgd-package \
  --baseline state/after-update --device /dev/sr0 --output state/rollback-new
```

Dopo accettazione e uscita riuscita, togliere e ripristinare l'alimentazione,
acquisire un nuovo dump in `state/restored` e verificarlo con
`verify-readback --state original --baseline state/restored`.
Questo rollback torna all'originale, non al vecchio candidato patchato.
