# NetSage AI - Human Review

This tool implements the human-review stage required by the project.

## Input

`ai_diagnosis_results.json`

## Output

`human_review_log.json`

Each case is explicitly marked:

- Accepted
- Edited
- Rejected

For Edited or Rejected cases, the reviewer can record what was wrong and the corrected diagnosis/fix.

## Run

Review every AI diagnosis:

```powershell
python human_review.py
```

Review selected cases:

```powershell
python human_review.py --cases 10 11 12
```

Set reviewer name:

```powershell
python human_review.py --reviewer "Gandhar"
```

Both options can be combined:

```powershell
python human_review.py --reviewer "Gandhar" --cases 10 11 12
```

## Important

Do not deliberately mark correct AI answers as wrong just to reach the project's requirement of five corrected cases. The log should contain genuine human corrections.

The tool reports how many Edited/Rejected cases have been recorded so you can track the Responsible AI requirement.
