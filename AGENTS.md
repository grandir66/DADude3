# AGENTS.md — DADude3

DaDude portato nativo: systemd, PostgreSQL, HTTPS, watchdog di auto-update. I 18
router API sono identici uno a uno al vecchio: è un superset stretto. Contiene anche
l'estratto DATIA/Cliconfig. Server in `dadude-server/`, agent in `dadude-agent/`;
avvio e installazione nel `README.md` e in `QUICK_START.md`.

**Repository pubblico** (`grandir66/dadude-native`): niente credenziali, nemmeno d'esempio.

## Regole del repo (dal `.cursorrules` del 10/01, fuso qui il 20/10)

- **Database: solo PostgreSQL.** SQLite non è mai supportato nel server: niente
  `sqlite:///`, `aiosqlite`, file `*.db`. Un riferimento a SQLite trovato nel codice
  si toglie.
- **Directory di produzione piatte**: il codice sta direttamente in
  `/opt/dadude-server/app/` e `/opt/dadude-agent/app/` (watchdog in
  `/opt/dadude-updater/`). Mai una sottocartella con lo stesso nome della madre
  (`/opt/dadude-server/dadude-server/`): prima di toccare un file in produzione si
  verifica il percorso con `ls -la`.
- **`.env`**: server in `/opt/dadude-server/.env` (o `data/.env`), agent in
  `/opt/dadude-agent/.env`; il server punta a PostgreSQL locale e ha SSL acceso.
- **Fermo dall'11/01**: alla ripresa si verifica prima che l'esercizio su PCT
  1600/1601 sia ancora attivo.

## Regole comuni (qui non si ricopiano)

Valgono le regole dell'area in `~/Progetti/AGENTS.md` e quelle di comportamento in
`~/.claude/AGENTS.md` (contesto su disco in `CONTEXT.md`, niente prove a caso,
loop di fine sessione). Questo file dice solo ciò che è di questo repo.
