## CPT_S 475 Semester Project

### Preprocessing Setup
Install Python packages
```
python -m venv venv
pip install -r requirements.txt
```

Download the dataset: https://www.unb.ca/cic/datasets/ids-2018.html
Make sure the "Original Network Traffic and Log data" folder is in the `source_data` folder

Preprocess data into DuckDB database
```
python preprocess.py
```