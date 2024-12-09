THREADS = 34

import joblib
from loguru import logger
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
import xgboost as xgb
from bayes_opt import BayesianOptimization
import numpy as np
import duckdb
import os

from config_source import SOURCE_DATA_DIR, SOURCE_DATA_TYPES

os.environ["MODIN_CPUS"] = str(THREADS)
os.environ["MODIN_ENGINE"] = "ray"
# import modin.pandas as pd
import pandas as pd
import swifter

USE_SOURCE_DATA = False

# Sample percent of the dataset to use
DATASET_SAMPLE_PERCENT = 1.0

SAMPLING_INTERVAL = "60s"

# Model name
MODEL_NAME = f"xgboost_rf_new_{DATASET_SAMPLE_PERCENT}_data_{SAMPLING_INTERVAL}"

TIMESTAMP_COL = "Timestamp"

# DROPPED_X_COLS = [
#     "Label",
#     "Timestamp",
#     "Dst Port",
#     "Dst IP",
#     "Src Port",
#     "Src IP",
#     "Flow ID",
# ]

DROPPED_X_COLS = ["date_minutes", "attack_type", "is_attack", "has_attack_ip"]

# TARGET = "Label"
TARGET = "is_attack"

# X_COLS = None
# X_COLS = [
#     "Protocol",
#     "Flow Duration",
#     "Tot Fwd Pkts",
#     "Tot Bwd Pkts",
#     "TotLen Fwd Pkts",
#     "TotLen Bwd Pkts",
#     "Fwd Pkt Len Max",
#     "Fwd Pkt Len Min",
#     "Fwd Pkt Len Mean",
#     "Fwd Pkt Len Std",
#     "Bwd Pkt Len Max",
#     "Bwd Pkt Len Min",
#     "Bwd Pkt Len Mean",
#     "Bwd Pkt Len Std",
#     "Flow Byts/s",
#     "Flow Pkts/s",
#     "Flow IAT Mean",
#     "Flow IAT Std",
#     "Flow IAT Max",
#     "Flow IAT Min",
#     "Fwd IAT Tot",
#     "Fwd IAT Mean",
#     "Fwd IAT Std",
#     "Fwd IAT Max",
#     "Fwd IAT Min",
#     "Bwd IAT Tot",
#     "Bwd IAT Mean",
#     "Bwd IAT Std",
#     "Bwd IAT Max",
#     "Bwd IAT Min",
#     "Fwd PSH Flags",
#     "Bwd PSH Flags",
#     "Fwd URG Flags",
#     "Bwd URG Flags",
#     "Fwd Header Len",
#     "Bwd Header Len",
#     "Fwd Pkts/s",
#     "Bwd Pkts/s",
#     "Pkt Len Min",
#     "Pkt Len Max",
#     "Pkt Len Mean",
#     "Pkt Len Std",
#     "Pkt Len Var",
#     "FIN Flag Cnt",
#     "SYN Flag Cnt",
#     "RST Flag Cnt",
#     "PSH Flag Cnt",
#     "ACK Flag Cnt",
#     "URG Flag Cnt",
#     "CWE Flag Count",
#     "ECE Flag Cnt",
#     "Down/Up Ratio",
#     "Pkt Size Avg",
#     "Fwd Seg Size Avg",
#     "Bwd Seg Size Avg",
#     "Fwd Byts/b Avg",
#     "Fwd Pkts/b Avg",
#     "Fwd Blk Rate Avg",
#     "Bwd Byts/b Avg",
#     "Bwd Pkts/b Avg",
#     "Bwd Blk Rate Avg",
#     "Subflow Fwd Pkts",
#     "Subflow Fwd Byts",
#     "Subflow Bwd Pkts",
#     "Subflow Bwd Byts",
#     "Init Fwd Win Byts",
#     "Init Bwd Win Byts",
#     "Fwd Act Data Pkts",
#     "Fwd Seg Size Min",
#     "Active Mean",
#     "Active Std",
#     "Active Max",
#     "Active Min",
#     "Idle Mean",
#     "Idle Std",
#     "Idle Max",
#     "Idle Min",
# ]

X_COLS = [
    "count_tcp_flags_res",
    "count_tcp_flags_cwr",
    "count_tcp_flags_ece",
    "count_tcp_flags_push",
    "count_tcp_flags_reset",
    "count_tcp_flags_ae",
    "count_tcp_flags_syn",
    "count_tcp_flags_urg",
    "count_tcp_flags_ack",
    "count_tcp_flags_fin",
    "avg_frame_time_delta",
    "stddev_frame_time_delta",
    "entropy_frame_len",
    "entropy_frame_time_delta",
    "entropy_tcp_time_relative",
]

if USE_SOURCE_DATA:
    MODEL_NAME += "_source_data"
    # load all csvs from the preprocessed data directory into a single dataframe
    logger.info("Loading preprocessed data...")

    if os.path.exists("training_data_source.csv"):
        dataset = pd.read_csv("training_data_source.csv")
        logger.info("Loaded data from csv file")
    else:
        # remove all duplicate header rows from each csv
        dataset = pd.DataFrame()
        if not os.path.exists(
            f"{SOURCE_DATA_DIR}/clean/Processed Traffic Data for ML Algorithms"
        ):
            for file in os.listdir(
                f"{SOURCE_DATA_DIR}/Processed Traffic Data for ML Algorithms"
            ):
                logger.info(f"Processing {file}...")
                df = pd.read_csv(
                    f"{SOURCE_DATA_DIR}/Processed Traffic Data for ML Algorithms/{file}",
                    low_memory=False,
                )

                logger.info(f"Removing duplicate headers from {file}...")
                # remove headers that were duplicated during concatenation
                # in this case, we just check for the existence of a cell with the value "Protocol"
                # use swifter so it runs on all cores
                df = df[df["Protocol"] != "Protocol"]

                logger.info("Converting data types...")
                # create any columns in DATA_TYPES.keys() that are missing
                # and fill them with NaN
                for col in SOURCE_DATA_TYPES.keys():
                    if col not in df.columns:
                        df[col] = np.nan

                # cast data types
                df = df.astype(SOURCE_DATA_TYPES)

                logger.info("Concatenating data with existing dataset...")
                dataset = pd.concat([dataset, df], ignore_index=True)
                logger.info(dataset.head())

        logger.info("Saving data to csv file for next time")
        dataset.to_csv("training_data_source.csv")

    logger.info("Loaded preprocessed data")
else:
    # check if we have the dataset in parquet format
    # if not, load it from the duckdb database
    if os.path.exists("training_data.parquet"):
        dataset = pd.read_parquet("training_data.parquet")
        logger.info("Loaded data from parquet file")
    else:
        logger.info("Loading data from the duckdb database...")
        # Load data
        con = duckdb.connect(database="data/pcap_metadata.duckdb", read_only=True)
        dataset = con.execute("SELECT * FROM merged_aggregated").df()
        con.close()
        # cache data to parquet so we don't have to load it again
        dataset.to_parquet("training_data.parquet")
        logger.info("Saved data to parquet file for next time")

# count rows before sampling
logger.info(f"Rows before sampling: {len(dataset)}")

# sample the dataset to make it smaller
dataset = dataset.sample(frac=DATASET_SAMPLE_PERCENT)

if USE_SOURCE_DATA:
    # map target to binary 0 or 1 depending of if it's 'Benign' or something else
    dataset[TARGET] = dataset[TARGET].map(lambda x: 0 if x == "Benign" else 1)

    # group by timestamp in intervals
    dataset[TIMESTAMP_COL] = pd.to_datetime(dataset[TIMESTAMP_COL], dayfirst=True)
    dataset["ts_interval"] = dataset[TIMESTAMP_COL].dt.floor(SAMPLING_INTERVAL)

    # aggregate the data
    dataset = (
        dataset.groupby(["ts_interval"], dropna=True)
        .agg(
            {
                TIMESTAMP_COL: "first",
                "Protocol": "first",
                "Label": "max",
                "Dst Port": "first",
                "Dst IP": "first",
                "Src Port": "first",
                "Src IP": "first",
                "Flow ID": "first",
                # the rest of the columns are averaged
                **{
                    col: "mean"
                    for col in dataset.columns
                    if col
                    not in [
                        TIMESTAMP_COL,
                        "Protocol",
                        "Label",
                        "Dst Port",
                        "Dst IP",
                        "Src Port",
                        "Src IP",
                        "Flow ID",
                    ]
                },
            }
        )
        .reset_index(drop=True)
    )


logger.info(dataset.head())

# print number of positive and negative samples
logger.info(f"Positive samples: {dataset[TARGET].sum()}")
logger.info(f"Negative samples: {len(dataset) - dataset[TARGET].sum()}")

# print the first few rows of the dataset
logger.info(dataset.head())

# print the count of each attack type
logger.info(dataset[TARGET].value_counts())

Y = dataset[TARGET].copy()
if X_COLS:
    X = dataset[X_COLS]
else:
    X = dataset.drop(DROPPED_X_COLS, axis=1)

# if any rows have values that are infinite, replace them with NaN
X = X.replace([np.inf, -np.inf], np.nan)
Y = Y.replace([np.inf, -np.inf], np.nan)

# log number of rows with NaN values
logger.info(f"Rows with NaN values: {X.isna().any(axis=1).sum()}")

# filter out rows with NaN values
Y = Y[X.notna().all(axis=1)]
X = X.dropna()

# print columns we're using for X and Y
logger.info(f"X: {X.columns}")
logger.info(f"Y: {Y.name}")

# print the types of each column
logger.info(X.dtypes)
logger.info(Y.dtypes)

logger.info("Splitting the data into train, test sets...")
X_train, X_test, Y_train, Y_test = train_test_split(
    X, Y, test_size=0.2, random_state=42, stratify=Y
)

# print sizes of train and test sets
logger.info(f"Train X size: {len(X_train)}")
logger.info(f"Test X size: {len(X_test)}")
logger.info(f"Train Y size: {len(Y_train)}")
logger.info(f"Test Y size: {len(Y_test)}")

D_train = xgb.DMatrix(X_train, label=Y_train)
D_test = xgb.DMatrix(X_test, label=Y_test)

# check to see if we have a model saved
if os.path.exists(f"models/{MODEL_NAME}.joblib"):
    logger.info("Model already trained, loading it from file...")
    model_best = joblib.load(f"models/{MODEL_NAME}.joblib")
    logger.info("Model loaded successfully!")
else:
    logger.info("Training the XGBoost classifier...")

    def run_with_params(
        max_depth, gamma, learning_rate, num_parallel_tree, subsample, colsample_bynode
    ):
        """
        Run the XGBoost classifier with the given parameters
        """
        params = {
            "max_depth": int(max_depth),
            "gamma": gamma,
            "learning_rate": learning_rate,
            "subsample": subsample,
            "tree_method": "hist",
            "num_parallel_tree": int(num_parallel_tree),
            "colsample_bynode": colsample_bynode,
            "nthread": THREADS,
            "objective": "binary:logistic",
        }

        def fpreproc(dtrain, dtest, param):
            label = dtrain.get_label()
            ratio = float(np.sum(label == 0)) / np.sum(label == 1)
            # scale weight by cross-validation ratio
            param["scale_pos_weight"] = ratio
            return (dtrain, dtest, param)

        # perform cross-validation
        # i.e. traing the model on a subset of the data and testing it on the rest
        # this is done multiple times to get a more accurate estimate of the model's performance
        cv = xgb.cv(params=params, nfold=5, metrics="auc", seed=42, dtrain=D_train, fpreproc=fpreproc)
        score_mean = cv["test-auc-mean"].iloc[-1]
        score_std = cv["test-auc-std"].iloc[-1]

        # Print the accuracy of the classifier
        logger.info(f"CV metric (AUC): {score_mean} (±{score_std})")
        # Print the parameters used
        logger.info(f"Parameters: {params}")

        # Return the mean error score
        return score_mean

    params = {
        "max_depth": (1, 100),
        "gamma": (0, 1),
        "learning_rate": (0.01, 1),
        "subsample": (0.5, 1),
        "num_parallel_tree": (50, 1000),
        "colsample_bynode": (0.5, 1),
    }

    logger.info("Tuning hyperparameters...")

    # Tune the hyperparameters
    # i.e. find the best settings for the training algorithm
    xgb_bo = BayesianOptimization(run_with_params, params)

    xgb_bo.maximize(init_points=5, n_iter=20)
    #xgb_bo.maximize(init_points=1, n_iter=1)

    logger.info("Best parameters found: ", xgb_bo.max["params"])
    logger.info("Training the model with the best parameters...")

    best_params = xgb_bo.max["params"]
    best_params["max_depth"] = int(best_params["max_depth"])
    best_params["num_parallel_tree"] = int(best_params["num_parallel_tree"])
    best_params["objective"] = "binary:logistic"
    best_params["nthread"] = THREADS
    best_params["tree_method"] = "hist"
    best_params["scale_pos_weight"] = float(np.sum(Y_train == 0)) / np.sum(Y_train == 1)

    model_best = xgb.train(best_params, D_train, num_boost_round=10)

    logger.info("Model trained successfully!")

    logger.info("Saving the model...")

    # save model to ./models directory
    joblib.dump(model_best, f"models/{MODEL_NAME}.joblib")

# test the model
logger.info("Testing the model...")
predict_dmatrix = xgb.DMatrix(X_test)
prediction = model_best.predict(predict_dmatrix)

# print predictions 
logger.info(prediction)

# map prediction from probability to binary
prediction = np.round(prediction)

# get number of positive and negative predictions
logger.info(f"Positive predictions: {np.sum(prediction)}")
logger.info(f"Negative predictions: {len(prediction) - np.sum(prediction)}")

logger.info("Accuracy: " + str(np.mean(prediction == Y_test)))
logger.info("\n" + classification_report(Y_test, prediction))
