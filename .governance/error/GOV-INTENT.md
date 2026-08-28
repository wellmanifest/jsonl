# GOV-INTENT

## Situation

Kody `GOV-INTENT-001`–`GOV-INTENT-003` oznaczają, że diff implementacyjny nie
ma ważnego, wcześniejszego mandatu. Kolejno: ticket nie był w stanie
implementacyjnym, `intent.json` jest nieobecny lub niepoprawny, albo intent nie
istniał w rodzicu pierwszego commita implementacyjnego.

## Meaning

Intent jest planem, który ma być przejrzany **zanim** powstanie kod. Ticket
scaffoldowany i zaimplementowany w jednym commicie nie spełnia tego wymogu,
nawet jeśli treść diffu jest poprawna: w rodzicu tego commita `intent.json` nie
istniał, więc nie było czego zatwierdzić.

`GOV-INTENT-003` jest osobnym faktem od `GOV-SCOPE-001`. Zakres może być
idealnie zgodny z `allowedPaths`, a mandat i tak nie powstał na czas.

## Safe resolution

1. Zbuduj gałąź w kolejności: commit planu, potem implementacja.

   ```
   plan(ticket-NNN): record intent      PLAN / WAIT_FOR_APPROVAL
   feat|fix|chore(...): implementation  IN_PROGRESS / EDIT
   chore(...): move to PUBLICATION      IN_PROGRESS / PUBLICATION
   ```

   Commit planu zawiera `project/ticket-NNN/**`, `TODO.md` i indeks ticketów.
   Nie zawiera żadnej ścieżki implementacyjnej.

2. `DONE / DONE` ustaw dopiero w osobnym governance-only closure, zbudowanym z
   zintegrowanej gałęzi domyślnej po trusted merge.

3. Gdy gałąź nie została jeszcze opublikowana, przebuduj ją. Gdy historia jest
   już opublikowana i zaufana, nie przepisuj jej — otwórz następcę z poprawną
   kolejnością i zamknij poprzednika bez merge'a.

## Verification

`./project/governance-check.sh` bez argumentów bada **drzewo robocze**, nie
historię commitów. Jednocommitowy ticket raportuje `GOV-PASS` w tym trybie i
mimo to zostaje odrzucony przez chronioną bramkę, która analizuje zakres.

Dowodem jest wyłącznie tryb zakresowy:

```sh
./project/governance-check.sh --base origin/main --head HEAD
```

Uruchom go przed każdym pushem gałęzi ticketowej. Wynik `GOV-PASS` z gołego
wywołania nie jest wystarczającym dowodem.

## Do not

- Nie traktuj `GOV-PASS` z domyślnego, bezargumentowego wywołania jako dowodu
  poprawnej kolejności commitów.
- Nie przepisuj opublikowanej, zaufanej historii, żeby wstawić brakujący commit
  planu; użyj następcy.
- Nie zamykaj ticketu na niescalonej gałęzi pełnego diffu.
- Nie łącz scaffoldu ticketu ze zmianą implementacyjną w jednym commicie, nawet
  gdy zmiana jest jednolinijkowa.

## Related rules

- `P-CORE-008`, `P-CORE-014`, `P-CORE-023`
- `C-TICKET-008`, `C-TICKET-017`
- `C-PUBLISH-003`, `C-PUBLISH-009`
