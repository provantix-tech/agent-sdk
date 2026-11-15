COST STATEMENT BUNDLE

This is cost evidence for AI and AI agents only. It supports an audit; it is not an audited financial statement.

What is in here
  statement/statement.json      the statement as frozen when the period was closed
  statement/cells.json          every figure the totals add up from: by day, agent, provider, model and the department, cost center and product tags
  statement/statement.csv       one line per figure, with its section and its kind, for finance
  statement/statement.html      a readable copy
  statement/chargeback/*.csv    one file per department, each with a total line; "(unallocated)" is its own file so the files add up to the total
  manifest.json                 every file with its hash, signed

What checking it proves
  The files are unchanged since the statement was issued (the manifest and its signature), and the stated totals are what the cells add up to: the published verifiers (Node, Python and the browser at provantix.tech/verify) add up statement/cells.json and check the totals by provider and model, each allocation, the cover total and the chargeback files against the stated total. A verifier older than this one still checks the files and the signature and does not add the figures up. You can also add statement/cells.json (or statement.csv) yourself.

What it does not prove
  That the cells are the right figures. They are the estimates frozen at close, from the organization's own price table. The provider's own figures are included as fetched, and are
  not an invoice. Nothing here says the spend was necessary or correct, and nothing says it was audited.

Every figure names its kind: estimated (from the price table), provider-reported (the provider's own figure) or reconciled (compared with the provider's figure).
