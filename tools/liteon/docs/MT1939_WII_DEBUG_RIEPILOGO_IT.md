# MT1939: problema di lettura Wii e tentativi di correzione

**Aggiornamento successivo:** individuato un timestamp READ non inizializzato
da C0, usato da un watchdog che genera esattamente `03/11/05`. Correzione e
confronto prima/dopo in emulazione sono descritti in
[MT1939_WII_WATCHDOG_IT.md](MT1939_WII_WATCHDOG_IT.md). Il 16 ottobre l'utente
ha fornito un primo probe positivo: tutti e quattro i C0 riescono e il raw
coincide con il settore prima ottenuto dopo READ(10). Il successivo dump
completo con redumper MT1939_MINIMAL termina con zero errori SCSI/EDC su
2.294.912 settori; l'utente riporta anche una ripartenza dopo Ctrl+C senza
errori. Il successivo readback fornisce due hash raw `fca70bec…` identici e
`full_image_matches_expected: true`, confermando il candidato watchdog-fix.
La prova C0 immediatamente dopo una partenza a freddo resta da documentare
esplicitamente. Il testo seguente conserva la cronologia precedente.

Aggiornato al 15 ottobre 2026, dopo il secondo report del probe sul candidato
«receive-fix». Questo documento riassume la conversazione e le evidenze locali;
non certifica che il port sia validato sul dispositivo.

## Stato attuale

Le letture raw Wii tramite il comando proprietario C0 falliscono inizialmente
con sense `03/11/05` e buffer vuoto. Un READ(10) nativo, pur restituendo
`05/30/02`, rende possibile la successiva lettura C0 dello stesso settore.
READ CD MSF restituisce lo stesso errore di READ(10), ma non sblocca C0.

Sono state implementate due correzioni firmware: una preparazione nativa prima
della lettura e l'estensione della classificazione dei comandi alla ricezione.
I report successivi mostrano ancora il problema. Per il primo di questi
candidati è disponibile un readback completo corrispondente; per l'ultimo
rimane da acquisire nella conversazione la conferma del readback e della
rimozione fisica dell'alimentazione. La firma INQUIRY è uguale in tutte le
build e non permette di distinguere il codice effettivamente in esecuzione.

Il workaround host READ(10) preliminare è la soluzione con evidenza fisica
positiva finora. Non è stato documentato un dump Wii completo con esito finale
e integrità verificata.

## Dispositivo e condizioni di prova

| Voce | Valore |
| --- | --- |
| Drive | ASUS BW-12B1LT, revisione 1.03 |
| Controller | MediaTek MT1939 |
| Firma firmware | OmniDrive 1.0.4 |
| Dispositivo Linux usato dall'utente | `/dev/sr0` |
| Disco | Wii noto funzionante, confermato dall'utente |
| Struttura rilevata | DVD-ROM, book type NINTENDO, un layer |
| Settori | 2.294.912 |
| Intervallo PSN | `0x030000`–`0x26047F` |
| Probe | LBA 0, un settore per richiesta |
| Lettura raw C0 DVD | 2064 byte |

Le prove sul drive sono eseguite dall'utente. Le verifiche nel repository
usano emulazione e trasporti simulati; non accedono al lettore dell'utente.

## Cronologia dei tentativi

### 1. Primo candidato nativo e supporto redumper

Il candidato iniziale con guardia sulle richieste a zero settori è stato
programmato. Il report di aggiornamento indicava 512 blocchi confrontati,
1026 comandi di aggiornamento e finalizzazione accettata dal trasporto.
La verifica successiva ha riportato `full_image_matches_expected: true`.

È stato aggiunto supporto MT1939 a redumper. Il test Wii con
`--dvd-raw --dump-read-size=1 --speed=4 --retries=2` falliva sin da LBA 0,
poi a ogni settore provato. Un controllo su DVD ordinario è stato riportato
senza errori: questo non dimostra il funzionamento della lettura Nintendo.

### 2. Variazione dei flag C0

Sono state provate quattro richieste con stessi LBA e numero di settori:

| Nome | CDB | Esito iniziale |
| --- | --- | --- |
| raw | `c0 01 00 00 00 00 00 00 00 01 00 00` | `03/11/05` |
| raw + FUA | `c0 09 00 00 00 00 00 00 00 01 00 00` | `03/11/05` |
| descrambling nativo | `c0 11 00 00 00 00 00 00 00 01 00 00` | `03/11/05` |
| descrambling nativo + FUA | `c0 19 00 00 00 00 00 00 00 01 00 00` | `03/11/05` |

Nei report che misurano il contenuto del buffer, tutti questi fallimenti
mostrano `buffer_nonzero_bytes: 0` e `complete: false`. Il residuo pari a zero
e il conteggio nominale di 2064 byte non dimostrano la ricezione di dati validi
quando il comando termina con errore. Il descrambling DVD nativo non convalida
da solo i dati Nintendo.

### 3. READ(10) preliminare: primo risultato positivo

Il confronto sullo stesso settore ha dato:

1. C0 FUA: errore `03/11/05`, buffer vuoto.
2. READ(10) FUA, `28 08 00 00 00 00 00 00 01 00`: errore `05/30/02`.
3. Identico C0 FUA: successo, 2064 byte, 2055 byte non nulli.

SHA-256 del settore raw riuscito, ripetuto identico nei report successivi:

```text
7ed3fad9d33f743571c2c4840a1566c31a9dc2ea6a4222d8d470ac488f1665f9
```

Primi 32 byte:

```text
00 03 00 00 11 12 52 5a 44 50 30 31 03 00 66 0c
0d 99 a8 06 50 c6 b9 5a 59 ff 8c 0e 99 ce 57 41
```

Questo prova una lettura ripetibile del settore dopo READ(10), non l'integrità
dell'intero disco né la validità di tutti i campi del settore.

Nel percorso firmware analizzato, il guard Nintendo di `DVDReadCmdHook`
restituisce `05/30/02` prima di chiamare il lettore DVD nativo. READ(10) può
quindi cambiare lo stato del drive pur non consegnando dati del disco.

### 4. Workaround in redumper

Una versione di redumper invia READ(10) prima del dump raw DVD, accetta il
rifiuto Nintendo atteso e mantiene i controlli sulle successive letture C0.
L'utente ha riportato oltre 10.000 settori senza errori e una seconda partenza
senza errori dopo Ctrl+C. In una precedente ripartenza era ricomparso l'errore
a LBA 0: lo stato del drive e la preparazione restano rilevanti.

Successivamente, su richiesta dell'utente, `/src/redumper` è stato ridotto
alle modifiche minime necessarie al supporto MT1939. La versione
`MT1939_MINIMAL` non esegue il READ(10) preliminare e ha riprodotto il guasto.
Il binario con workaround è conservato separatamente in
`dump/redumper-diagnostics/redumper-with-read10-workaround.zip`.

### 5. Prima correzione firmware: MtNativeReadPrepare

L'analisi ha individuato che `MtNativeReady(1)` non applica a C0 la preparazione
riservata agli opcode READ riconosciuti. È stata aggiunta una chiamata esplicita
a `MtNativeReadPrepare()` dopo la validazione e la guardia zero settori.

La routine nativa è all'alias basso `0x398`, corrispondente a flash `0x10398`.
Esegue OR di `0x000b0000` su `0x04041050` e di `0x100` su `0x04040098`,
preservando lo stato degli interrupt.

Le verifiche offline hanno confermato la preparazione prima dell'ingresso nei
lettori e nelle richieste ripetute. Il candidato è stato aggiornato direttamente
e l'utente ha fornito due letture complete identiche al raw atteso `91cbe710…`,
seguite da `full_image_matches_expected: true`.

Un tentativo precedente di readback era fallito con `FileExistsError`, mentre
il comando successivo aveva verificato la vecchia directory. Quel risultato
non era una nuova acquisizione; è stato sostituito da letture effettivamente
completate in una nuova directory.

**Esito ottico:** i quattro flag C0 falliscono ancora; READ(10) continua a
sbloccare la lettura. La preparazione aggiunta non è sufficiente, a condizione
che il codice aggiornato sia stato ricaricato dopo la rimozione di alimentazione.

### 6. Confronto READ CD MSF / READ(10)

È stata individuata una seconda differenza prima del dispatcher:
READ(10), READ(12) e READ CD azzerano i 16 bit inferiori del registro
`0x040400c4` alla ricezione; C0 e READ CD MSF non lo fanno nel codice originale.
READ CD MSF e READ(10) eseguono invece entrambi la preparazione successiva.

Il probe usa READ CD MSF con CDB
`b9 00 00 00 02 00 00 02 01 f8 00 00` e quindi confronta:

| Passaggio | Risultato riportato |
| --- | --- |
| C0 FUA iniziale | `03/11/05`, buffer vuoto |
| READ CD MSF | `05/30/02` |
| C0 FUA dopo MSF | `03/11/05`, buffer vuoto |
| READ(10) FUA | `05/30/02` |
| C0 FUA dopo READ(10) | Successo, stesso SHA-256 del settore |

Il risultato sosteneva una differenza specifica tra i due percorsi nativi,
ma non isolava il registro: il probe non legge né scrive MMIO direttamente.

### 7. Seconda correzione firmware: classificazione alla ricezione

La patch aggiunge C0 al controllo di 18 byte a flash `0x101a2`, eseguito
attraverso l'alias basso `0x1a2`. Eliminando due ricaricamenti ridondanti
dell'opcode, entra un confronto aggiuntivo senza nuova routine o allocazione
RAM. C0 percorre il blocco nativo a `0x1b4` che azzera la metà bassa di
`0x040400c4`.

Rispetto al candidato precedente cambiano nove byte di istruzioni e tre byte
del checksum principale. Restano invariati payload C, boot, finestra
autenticata e code riservate. La preparazione del tentativo precedente resta
presente. Tutti i pacchetti C0 ricevono il nuovo setup prima della validazione;
la richiesta zero settori continua a non entrare nel lettore o avviare DMA.

Verifiche eseguite:

- 768 casi di ricezione: tutti i 256 opcode con tre valori iniziali del registro.
- Confronto di scritture e chiamate non-C0 rispetto al firmware originale.
- 12 sequenze ripetute dalla ricezione all'ingresso dei lettori CD, DVD,
  DVD-RAM e BD, senza READ preliminare.
- Audit completo del port, loader e programmatore nativo.
- Transizioni emulate dai candidati `5eac461d…` e `56432d9b…` al nuovo,
  per NOR `c22015` e `c22415`.
- Suite: 99 test esaminati, 98 superati, uno saltato per assenza della
  directory CMake configurata. Il build di produzione è verificato anche
  tramite gli altri test in directory temporanee.

**Report fisici successivi:** tutti i flag C0 falliscono ancora. Anche il nuovo
confronto MSF/READ(10) ripete esattamente la sequenza della tabella precedente:
solo dopo READ(10) C0 riesce, con lo stesso SHA-256. Nell'ultimo report i tempi
sono circa 0,271 s per C0 iniziale, 0,012 s per MSF, 0,267 s per C0 dopo MSF,
0,012 s per READ(10), 1,277 s per C0 riuscito.

Non è ancora stato fornito in conversazione l'esito del readback del candidato
`535510d8…`, né una conferma esplicita della rimozione fisica di alimentazione.
Questa lacuna impedisce di attribuire senza condizioni l'ultimo risultato al
nuovo codice. Se entrambi sono confermati, l'azzeramento del registro non è
sufficiente e non va presentato come soluzione del bug.

## Identificazione esatta delle immagini

Gli hash decoded identificano le immagini firmware; gli hash raw identificano
il flusso di lettura cifrato con la sessione prevista dal runner. Non sono
intercambiabili. Tutti i candidati pubblicizzano OmniDrive 1.0.4.

| Immagine | SHA-256 decoded |
| --- | --- |
| Originale | `c0a5d073ccfce917712a459b73bff51bcf42bf41ee0703575c0408a59828f84d` |
| Candidato iniziale | `5eac461d23ebcd42ed80c53705822619d245d14a322396c1cb43983b65f9906d` |
| Native read preparation | `56432d9b48213aea5ea4f82e0146e319083ec609a426b1510a45b2c8cad5dcf9` |
| Receive fix | `535510d835843bca12094eb8380564574cc920978e7b08bb8b5c63bd923b0c56` |

| Immagine | SHA-256 raw atteso |
| --- | --- |
| Originale | `47e8882c0d0f983df709186142ba81ca91d62661dd4352531c54c8ac1dd6a379` |
| Candidato iniziale | `1a304a8379612a5e813d862b33fcf9bf2eeb959a8b253d1f2935388889016a94` |
| Native read preparation | `91cbe71079a1865bd2f9a93eba963a3e4b8fb49f5dc0bba9fda087d568435dd1` |
| Receive fix | `7e27a638e6a2c89fd9b2ef2115f30648b96135ab9862cd8becadd002fd921d58` |

Staging del receive fix:
`80650782ef40155838944433f513b1e32993efe17449b9875dd1a7e092f4f3e9`.

## Aggiornamento e significato dei risultati

Il runner supporta `apply --force-source` per passare direttamente da una
sorgente compatibile al candidato fissato. Conserva controlli su identità,
sessione, due backup identici, regioni preservate e codice di aggiornamento;
il confronto completo live con il backup precede i comandi di scrittura.
Non accetta una destinazione arbitraria. Il boot non viene aggiornato e la
finalizzazione viene tentata una sola volta.

- `transport_accepted_requires_cold_readback`: il trasporto ha accettato la
  finalizzazione; non prova il contenuto fisico finale.
- `full_image_matches_expected: true`: il readback fornito corrisponde
  all'immagine attesa dal runner usato. Occorrono acquisizione fresca e runner
  del pacchetto corretto.
- Il readback non prova che il codice attualmente in RAM sia stato ricaricato.
- `flash_ready: false` e `patch_hardware_validated: false` non vengono
  trasformati in una validazione ottica dal successo dei test offline.

## Limiti e prossimi passi

La prima ipotesi era una preparazione READ mancante; la seconda attribuiva
rilievo al registro di ricezione. Entrambe hanno prodotto differenze concrete
nel codice, ma non una risoluzione ottica dimostrata. Il confronto MSF/READ(10)
non autorizzava ad attribuire l'effetto a un singolo registro.

I test emulati usano MMIO come memoria modellata, helper esplicitamente
simulati e un modello dell'alias basso. Non riproducono tutti gli effetti
hardware, gli interrupt reali o la dinamica ottica. Le prove che partono dal
dispatcher non coprono la ricezione; quelle nuove coprono ricezione e ingresso
nel lettore, ma non l'intero ciclo reale del comando.

I prossimi passi sono:

1. Acquisire conferma del readback receive-fix e della rimozione di alimentazione.
2. Confrontare il ciclo completo READ(10)/READ CD MSF/C0, includendo gli effetti
   prima del dispatcher e il completamento del comando. Il chiamante esterno
   del dispatcher è `0x1bdea`; il dispatcher usato nei test è `0x1b14e`.
3. Esaminare anche gli altri rami specifici READ(10) nella ricezione, compreso
   il tratto all'alias `0xd6`–`0xf8`, e separare osservazioni da interpretazioni
   sul loro ruolo. Non è stata ancora dimostrata la loro causalità.
4. Preferire un confronto diagnostico che isoli una differenza a ulteriori
   flash basati soltanto sulla parità dei registri in emulazione.
5. Per validare la soluzione: C0 riuscito a freddo senza preparazione host,
   ripartenza dopo interruzione, dump completo con controlli EDC e controlli
   sugli altri supporti interessati dal port.

Per proseguire intanto l'acquisizione, READ(10) preliminare rimane un workaround
con risultato positivo osservato. Non dimostra che C0 sia autonomo.

## Riferimenti e artefatti locali

I percorsi `dump/` e `dist/` sono relativi alla radice del repository e possono
essere esclusi da Git. Le istruzioni storiche possono riferirsi a pacchetti
superati: per la procedura corrente usare [FLASH_MT1939_IT.md](FLASH_MT1939_IT.md).

| Riferimento | Contenuto |
| --- | --- |
| `asm/liteon/mt1939.asm` | Patch della classificazione alla ricezione |
| `asm/ASUS_BW-12B1LT_1.03.asm` | Indirizzi della patch e simboli nativi |
| `src/liteon/mt1939.c` | Adapter C0 e preparazione prima della lettura |
| `tools/liteon/patch_verify/verify_native_read_preparation.py` | Confronti offline di ricezione e preparazione |
| `tests/test_liteon_native_adapter.py` | Regressioni adapter e ricezione |
| `tests/test_liteon_native_trial.py` | Controlli del runner e transizioni simulate |
| `dump/redumper-diagnostics/mt1939_receive_probe.py` | Probe fisico di sola lettura |
| `dump/mt1939-receive-physical-observation.json` | Sintesi del confronto fisico precedente al receive-fix |
| `dump/mt1939-receive-fix-evidence.json` | Audit offline legato a immagine e sorgenti |
| `dump/mt1939-receive-fix-tests-complete.log` | Esito della suite da 99 test |
| `dump/mt1939-receive-fix-delta.json` | Differenze binarie rispetto al candidato precedente |
| `dump/bw12b1lt-native-receive-fix-package/` | Payload del candidato e rollback originale |
| `dist/bw12b1lt-mt1939-receive-fix.zip` | Pacchetto consegnato per l'ultimo test |

SHA-256 dello ZIP receive-fix consegnato:
`082741d299052e5f6d1ba01ec2795f551e3778cd59a2a8c4d8dbe6fc396963de`.
Questo riepilogo, scritto dopo i report di fallimento, non è incluso in quello ZIP.
