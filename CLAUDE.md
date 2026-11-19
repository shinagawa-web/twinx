# CLAUDE.md

The experiment and its loop are described in README.md. A scheduled run of the loop follows docs/loop.md.

## Log every human intervention

Where and how often a human steps in is one of the results of this experiment, so every input from a human is recorded in `docs/interventions.md`.

- Add one row whenever a human decides, corrects what you proposed or wrote, approves a proposal, or asks a question whose answer changes the plan. This includes inputs about the environment, the tooling or the documents, not only the code.
- Add the row as it happens, before replying, and put it in the same pull request as the change it caused. main only accepts changes through pull requests that pass the `judge` check.
- Use the kinds defined at the top of that file.

## Language

Everything in the repository is written in English: documents, code comments, test cases and commit messages.
