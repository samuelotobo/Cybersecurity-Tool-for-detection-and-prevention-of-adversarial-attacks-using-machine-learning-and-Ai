This folder is an archive, not part of the running project.

It holds the working files used to PRODUCE reports/Security_Monitor_Project_Report.docx:
the screenshot-capture scripts, the raw screenshots themselves (project_report_assets/),
the python-docx generator script (generate_report.py), and an older superseded draft
of the report (Security_Monitor_Detailed_Project_Report_OLD.docx).

None of this is needed to run, test, or build the app. If you just want to understand
or continue the project, you want these instead:

    README.md                          feature list and reference docs
    PROJECT_GUIDE.txt                  humanized run + continue guide
    HOW_TO_RUN_AND_TEST.md             short run/test checklist
    reports/Security_Monitor_Project_Report.docx   the current project report
    reports/project_walkthrough.html   narrated architecture walkthrough

This archive is kept only in case someone wants to regenerate or update the report
later — e.g. after retraining the model or adding a new detector, re-run
generate_report.py (it will need fresh screenshots to match).
