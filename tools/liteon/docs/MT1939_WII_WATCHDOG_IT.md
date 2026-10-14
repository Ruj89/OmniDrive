# MT1939: timestamp READ mancante e watchdog 03/11/05

## Risultato dell'analisi del 15 ottobre 2026

È stata trovata e corretta una terza omissione, distinta dalle due preparazioni
già tentate. Il confronto emulato fra il receive-fix `535510d8…` e il nuovo
candidato `db7979b1…` riproduce esattamente `03/11/05` nel primo e ne evita
l'insorgenza immediata nel secondo, a parità di stato iniziale.
Il 16 ottobre sono arrivati un probe fisico positivo e un dump Wii completo
con zero errori SCSI/EDC, descritti sotto.
La validazione completa del port resta aperta.

Alla ricezione, `0x15e` (flash `0x1015e`) chiama `0x1ca48`. Per i soli opcode
READ(10) e READ(12), questa routine:

- incrementa il contatore byte a `0x020007d4`;
- copia il tick a 16 bit da `0x020007b2` a `0x020007ba`.

Il corpo di aggiornamento comincia a `0x1ca56`. C0 e READ CD MSF non lo
eseguono. I precedenti test di ricezione sostituivano **l'intera routine
0x1ca48 con uno stub**: il confronto dei registri non poteva rilevare questa
differenza. Ora ne vengono eseguite le istruzioni reali.

La lettura raw DVD/BD condivisa converte poi C0 in A8 (READ(12)). Il ramo
nativo a `0x1bb670` riconosce A8; se il valore restituito dall'helper di
avanzamento `0x40390` resta invariato, il ramo `0x1bb77c` confronta il tick
corrente con `0x020007ba`. La differenza è calcolata modulo 65536.
Oltre **350 tick**, le istruzioni `0x1bb790`–`0x1bb7a0` scrivono proprio
`03/11/05`, prima della gestione dell'errore a `0x1bb726`.
Non è stata determinata l'unità fisica del tick.

Questo spiega un meccanismo coerente con tutti i report: READ(10) rinnova il
timestamp prima del rifiuto Nintendo; MSF non lo rinnova; C0 usa in seguito
il watchdog READ(12) con un timestamp che non ha inizializzato. Le precedenti
patch MMIO non correggevano questo stato. Resta da dimostrare sul dispositivo
che sia proprio questo ramo a produrre l'errore osservato.

Il ramo `0xd6`–`0xf8` è diverso: imposta il bit 0 di `0x02000629` solo per
READ(10), con intervallo almeno 10 e lunghezza precedente pari a 1; gli altri
opcode lo azzerano. Non è stato modificato e non è necessario per riprodurre
il timeout nel modello. Non si attribuisce a quel bit una causalità fisica.

## Correzione

L'adapter chiama il corpo nativo `MtNativeReadAccount` (`0x1ca56`) dopo la
validazione, la guardia zero settori e `MtNativeReadPrepare`, prima del cambio
opcode e dell'ingresso nei lettori DVD, DVD-RAM e BD. Si riusa la routine
nativa senza allocare RAM o modificare il watchdog. Il contatore conserva
il suo incremento modulo 256.

CD non converte il comando in A8 e non riceve questo aggiornamento. Richieste
vuote o rifiutate non modificano contatore/timestamp. Una nuova richiesta valida
rinnova sempre lo stato; non occorre affidarsi al precedente READ host.
Il timeout normale dopo 351 tick senza avanzamento resta attivo.

## Verifiche riproducibili

`verify_native_read_watchdog.py`, richiamato dalla suite e dall'audit completo,
controlla 256 opcode nella routine di ricezione originale, 81 casi raw
(tre supporti, tre tick, tre età del timestamp, tre richieste ripetute) e
quattro casi esclusi. Copre soglia 350/351, riporto del tick a 16 bit e del
contatore a 8 bit. L'audit completo richiede ora la sezione `read_watchdog`.

Il confronto locale delle due immagini effettive è in
`dump/mt1939-watchdog-before-after.json`: tick 1000, timestamp iniziale 0,
stesso C0 DVD FUA, helper di avanzamento modellato a zero. Il vecchio adapter
lascia timestamp 0 e il watchdog genera `03/11/05`; il nuovo lascia timestamp
1000 e prosegue senza quel sense. L'emulazione si ferma prima del cleanup
d'errore e non riproduce trasferimento ottico, scheduling o interrupt reali.

Artefatti: `dump/mt1939-watchdog-evidence.json`,
`dump/mt1939-watchdog-tests.log`, `dump/mt1939-watchdog-hashes.json`.
Build con GCC ARM 14.2.1; il candidato differisce dal receive-fix in 593 byte
(il payload compilato cambia anche gli offset delle funzioni successive).
Boot, finestra autenticata e code riservate restano invariati.

Esito complessivo: 100 test Lite-On esaminati, 99 superati e uno saltato
per assenza di una directory CMake già configurata. La prima esecuzione aveva
due errori per NumPy assente e saltava anche CMake assente: installate queste
dipendenze in un ambiente temporaneo, entrambi i test di confronto e la suite
build sono passati. I log dei riesami sono
`dump/mt1939-watchdog-compare-tests.log` e `dump/mt1939-watchdog-build-tests.log`;
il primo log completo conserva fedelmente gli errori iniziali. Sono passati
anche i 10 test del probe. Le transizioni emulate dai tre candidati precedenti
al nuovo sono passate su entrambe le NOR c22015 e c22415.

| Flusso | SHA-256 nuovo candidato |
| --- | --- |
| Decoded | `db7979b10529b30732935dea22f12b4560f63316fc8da6fd6dac5eb3b951e413` |
| Raw atteso | `fca70becd9db7ae28253fec388db3ba6fd834889de08d73a161348c82e92dc5f` |
| Staging | `fd78ec34cc239d5589ced7bc5a5152217340f87defccb71c29e0ea10f9843603` |

## Primo report fisico positivo: 16 ottobre 2026

L'utente ha fornito il report del probe su `/dev/sr0`, ASUS BW-12B1LT 1.03,
OmniDrive 1.0.4, LBA 0 e un settore per richiesta. Tutti i comandi C0
terminano con status, host_status e driver_status pari a zero, senza sense,
2064 byte trasferiti, residuo zero e `complete: true`.

| Flag | Tempo (s) | Byte non nulli | SHA-256 |
| --- | --- | --- | --- |
| raw 01 | 1,307 | 2055 | `7ed3fad9d33f743571c2c4840a1566c31a9dc2ea6a4222d8d470ac488f1665f9` |
| raw FUA 09 | 0,050 | 2055 | `7ed3fad9d33f743571c2c4840a1566c31a9dc2ea6a4222d8d470ac488f1665f9` |
| descrambling 11 | 0,002 | 2056 | `a64a4d68f01402adab08ab3ec8a92e06d522e75fad7def06aeb176363ec12805` |
| descrambling FUA 19 | 0,049 | 2056 | `a64a4d68f01402adab08ab3ec8a92e06d522e75fad7def06aeb176363ec12805` |

Il report contiene INQUIRY seguito dai quattro C0, senza READ(10) nella
sequenza registrata. Le due letture raw coincidono con il settore prima
ottenuto dopo READ(10). Le due letture con descrambling coincidono fra loro;
il loro hash diverso non costituisce una verifica dell'integrità Nintendo.

È una conferma fisica positiva della lettura del settore nel contesto della
prova del watchdog-fix. Il solo report non documenta i comandi precedenti al
probe, la rimozione di alimentazione o il readback del candidato `db7979b1…`:
INQUIRY 1.0.4 non distingue le build. Quel singolo report non documenta un
dump completo o EDC; il successivo log redumper è riportato sotto.
Il successo sostiene la correzione, senza certificare l'intero port.

## Dump Wii completo: 16 ottobre 2026

L'utente ha fornito il log concluso con `*** END` di redumper
`MT1939_MINIMAL`, avviato alle 09:57:06 su `/dev/sg0`, ASUS BW-12B1LT 1.03,
OmniDrive 1.0.4. Parametri:
`--dvd-raw --dump-read-size=1 --speed=4 --retries=2`.
Questa build non include la preparazione host READ(10). L'utente ha inoltre
riportato interruzione con Ctrl+C e successiva ripartenza senza errori;
il log finale da solo non ricostruisce l'interruzione.

| Voce | Risultato riportato |
| --- | --- |
| Disco | The Legend of Zelda Twilight Princess, RZDP01, versione 0 |
| Supporto | NINTENDO, un layer, PSN `0x030000`–`0x26047F` |
| Settori READ CAPACITY / PHYSICAL | 2.294.912 / 2.294.912 |
| Errori SCSI / EDC | **0 / 0** |
| ISO | `dump_261016_095706_sg0.iso` |
| Dimensione | 4.699.979.776 byte, pari a 2.294.912 × 2048 |
| CRC32 | `576d9391` |
| MD5 | `c46c133885383f96e7515c5cefd152d2` |
| SHA-1 | `c708744c08d499962ad5760ab1b76748dea9914b` |

Il dump completo con EDC senza errori e la ripartenza riuscita costituiscono
evidenza fisica positiva per il caso Wii originariamente guasto. Gli hash
identificano l'ISO prodotta; non è stato effettuato un confronto con un dump
indipendente o un catalogo esterno. Il valore 5799 s è riportato dal log alla
fase `DUMP::EXTRA`, non viene interpretato come misura autonoma del tempo totale.

## Readback successivo al dump: candidato confermato

Dopo le istruzioni di rimozione del disco, spegnimento completo e riaccensione,
l'utente ha fornito l'esito del readback e di `verify-readback --state candidate`.
Le due letture hanno lo stesso SHA-256 raw:
`fca70becd9db7ae28253fec388db3ba6fd834889de08d73a161348c82e92dc5f`.
`reads_match` è vero e il verificatore restituisce
`full_image_matches_expected: true`. È il flusso raw atteso del candidato
watchdog-fix decoded `db7979b1…`: l'immagine installata è ora confermata.

I campi `image_verified: false` e `hardware_validated: false` del lettore
generico non annullano il confronto completo effettuato dal verificatore
specifico. `flash_ready: false` resta il flag conservativo del runner;
non è un errore di readback e non cambia automaticamente in seguito ai test.
L'output da solo non certifica la rimozione fisica dell'alimentazione.

Con probe positivo, dump Wii completo con zero errori SCSI/EDC, ripartenza
riuscita e readback corrispondente, il caso Wii originariamente segnalato ha
un esito fisico positivo sul candidato corretto. I flag generali del pacchetto
non vengono modificati sulla base di questo singolo supporto Wii.

## Validazione fisica da completare

Usare il nuovo pacchetto e il relativo runner, come descritto in
[FLASH_MT1939_IT.md](FLASH_MT1939_IT.md). I pacchetti precedenti conservano
le loro immagini e non installano questa correzione. INQUIRY resta 1.0.4.

Il readback completo corrispondente, il dump completo Wii con EDC e la
ripartenza dopo interruzione hanno ora un esito positivo riportato.
Per estendere la validazione, documentare C0 subito dopo una partenza a freddo
senza preparazione READ(10) e dopo inattività, oltre ai controlli su DVD
ordinario, CD e BD. `flash_ready` e `patch_hardware_validated` restano falsi
nel pacchetto sperimentale; non rappresentano il risultato dei singoli test.
