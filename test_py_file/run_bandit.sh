#!/bin/bash
bandit -r ./ -f html -o bandit_report_all.html
bandit -r ./ >> bandit_report_all.txt
