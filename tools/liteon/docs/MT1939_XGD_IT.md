# MT1939: rilevamento XGD (Xbox 360) e lettura del security sector

## Sintomo

Con il candidato watchdog `db7979b1…`, redumper legge di un disco Xbox 360
(Skate 2, XGD2) solo la partizione video: READ CAPACITY e lunghezza fisica
valgono entrambe 2724 settori, quindi la modalità Xbox non parte e la
partizione di gioco non viene letta. Il security sector è comunque leggibile
con C0 (`PSN 0xFD021E`, identificatore `0xE1`, layer0 end `0x20339F`).

`EnableXGD` (src/main.c) deve estendere `lastSector` (`0x020006B8`), da cui la
READ CAPACITY DVD nativa (`0xC8B20`) risponde `lastSector − 0x30000`.

## Cause trovate sul drive

Osservate con la lettura nativa di memoria `F1 02`: stato RAM, settore copiato
in `+0x6800` della struttura disco e una traccia temporanea per tentativo.

1. **Lettura del layer 1 con il PSN grezzo.** MT1959 legge il security sector
   con `ReadDiscData(8, 0x10)` e il PSN del layer 1. Su MT1939 nessuna lettura
   nativa usa PSN grezzi sul layer 1: il firmware imposta un indirizzo lineare,
   chiama il controllo layer e legge con area 0 (`0xCA4DA`):
   `startAddress = LBA + 0x30000`, `transferLength = n`,
   `MtNativeDVDCheckLayer(2)`, `MtNativeReadDiscData(0, n)`. Il lettore
   riconverte l'indirizzo in PSN (`0xCC8CE`, OTP: `addr − 2·(layer0End+1)`).
   Il byte di modalità del lettore vale `seekLayer + area`: 1 nel percorso
   nativo, 9 con l'area MT1959 (5 con l'area 4 del primo tentativo).
2. **Momento della lettura.** Anche con la sequenza nativa, durante il
   riconoscimento (`Mt1939ReadDVDTOCHook`, dentro `ReadDVDTOC`) la lettura
   fallisce in tutti e 5 i tentativi senza sense: il contatore hardware dei
   settori rimanenti (`0x040D0014`) non arriva a zero. La preparazione nativa
   della lettura DVD (`0xA25C2`) avviene solo dopo l'hook; la lettura C0 dello
   stesso indirizzo dopo il caricamento funziona.

Traccia fisica del secondo punto (layer check e area 0 già applicati):

```
attempt 0: linear 0x0312F0  DVDCheckLayer 2  seekLayer 1  ReadDiscData 0  sense 00/00/00
...
attempt 4: linear 0x0313F0  DVDCheckLayer 2  seekLayer 1  ReadDiscData 0  sense 00/00/00
```

## Correzione (src/liteon/mt1939.c)

- `ReadDiscData`: per l'area 8 converte il PSN con `dvd_psn` (come C0),
  imposta `transferLength`, chiama `MtNativeDVDCheckLayer(2)` e legge con
  area 0. `startAddress` resta il PSN per i tentativi di `EnableXGD`.
- `Mt1939ReadDVDTOCHook` non legge più: per un DVD OTP doppio strato scrive
  il segno `XGDP` in `+0x6FFC` della struttura disco (coda inutilizzata del
  settore `0x6800`), riscritto a ogni riconoscimento DVD.
- `Mt1939DVDReadCapacityHook` (dispatcher `0x1B500`, chiamata a `0xC8B20`):
  alla prima READ CAPACITY DVD con il segno attivo lo cancella, esegue
  `EnableXGD` preservando stato della richiesta e sense, poi chiama il
  gestore nativo. Le READ CAPACITY successive non rileggono.
- Temporaneo: una traccia per tentativo in `+0x6FB0` (marcata `shortcut:`),
  sovrascritta dal settore copiato quando la lettura riesce. Va rimossa con il
  prossimo candidato.

## Risultato fisico (23 novembre 2026)

Candidato `e9691709…`, Skate 2 dopo spegnimento completo:

| Valore | Prima | Dopo |
| --- | --- | --- |
| `+0x6800` | vuoto | `e1 0f 31 10 … 00 20 33 9f` |
| `layer0End` | `0x0003086F` | `0x0020339F` |
| `lastSector` | `0x00030AA3` | `0x003D6103` |
| READ CAPACITY | 2724 | 3825924 |

| Hash | Valore |
| --- | --- |
| Decoded | `e96917094cd65dfc0ef632b6a5162fe9bb1ddd949b7122a5ad92ff529a00aab7` |
| Raw atteso | `fcaff19ad698864f52e7709f92e503f28b28c00ab911cdcbe78a7d136752ea83` |
| Staging | `7e2d226a97022515d6a7c77b3399128bb670a9f4c76213f1154a985df45a80d8` |

Verificato solo XGD2. Restano da provare XGD1, XGD3, DVD doppio strato non
Xbox (atteso: `EnableXGD` si ferma al controllo DMI) e il dump completo con
redumper. La prima READ CAPACITY dopo il caricamento di un disco XGD può
richiedere qualche secondo in più per la lettura del layer 1.

## Verifica offline

`patch_verify/verify_native_media.py` esegue l'hook di riconoscimento (nessuna
lettura, segno impostato solo per DVD OTP doppio strato), poi due READ
CAPACITY: la prima chiama il controllo layer e il lettore con indirizzo
lineare, area 0 e 16 settori, la seconda non rilegge. La geometria e il TOC
restano verificati come prima. `patch_build/native_adapter.py` include il sito
`0x1B500` fra gli hook rivisti e nella regressione del dispatcher.

## Diagnostica fisica

Sola lettura, senza sudo. Appena dopo l'accensione, prima di altre letture C0
(che riempiono la cache e cambiano `startAddress`/`seekLayer`):

| Comando nativo | Uso |
| --- | --- |
| `F1 02 <indirizzo 4 byte> 04 00 00 00 00 00` | Una parola di memoria CPU, restituita come valore (byte di memoria invertiti a gruppi di 4) |
| `F1 06 <offset 4 byte> <lunghezza 4 byte>` | Cache da 8 MiB a partire da `memoryStart` (`0x01800000`), in ordine di memoria |

La struttura disco è a `memoryStart + discStructOffset` (`0x01FCB100` sul
campione): PFI `+0x5000`, DMI `+0x5800`, security sector `+0x6800`. La cache
contiene slot da `0x950` byte con il PSN in chiaro ai byte 1–3; i dati
principali possono restare scramblati. Le letture successive (montaggio del
sistema operativo, C0) sovrascrivono la cache, quindi l'assenza di un blocco
non dimostra che la lettura sia fallita: fanno fede il settore copiato e la
traccia.
