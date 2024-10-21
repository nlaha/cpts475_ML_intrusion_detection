THREADS = 35

import joblib
from loguru import logger
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
import xgboost as xgb
from sklearn.model_selection import (
    train_test_split,
)
from bayes_opt import BayesianOptimization
import numpy as np
import duckdb
import os

os.environ["MODIN_CPUS"] = str(THREADS)
import modin.pandas as pd
import swifter

MODEL_NAME = "xgboost_rf"
USE_SOURCE_DATA = True
SOURCE_DATA_DIR = "/home/nlaha/storage"

DATA_TYPES = {
    "Dst Port": "Int64",
    "Src Port": "Int64",
    "Protocol": "Int64",
    "Timestamp": "string",
    "Flow Duration": "Int64",
    "Tot Fwd Pkts": "Int64",
    "Tot Bwd Pkts": "Int64",
    "TotLen Fwd Pkts": "Int64",
    "TotLen Bwd Pkts": "Int64",
    "Fwd Pkt Len Max": "Int64",
    "Fwd Pkt Len Min": "Int64",
    "Fwd Pkt Len Mean": "float64",
    "Fwd Pkt Len Std": "float64",
    "Bwd Pkt Len Max": "Int64",
    "Bwd Pkt Len Min": "Int64",
    "Bwd Pkt Len Mean": "float64",
    "Bwd Pkt Len Std": "float64",
    "Flow Byts/s": "float64",
    "Flow Pkts/s": "float64",
    "Flow IAT Mean": "float64",
    "Flow IAT Std": "float64",
    "Flow IAT Max": "Int64",
    "Flow IAT Min": "Int64",
    "Fwd IAT Tot": "Int64",
    "Fwd IAT Mean": "float64",
    "Fwd IAT Std": "float64",
    "Fwd IAT Max": "Int64",
    "Fwd IAT Min": "Int64",
    "Bwd IAT Tot": "Int64",
    "Bwd IAT Mean": "float64",
    "Bwd IAT Std": "float64",
    "Bwd IAT Max": "Int64",
    "Bwd IAT Min": "Int64",
    "Fwd PSH Flags": "Int64",
    "Bwd PSH Flags": "Int64",
    "Fwd URG Flags": "Int64",
    "Bwd URG Flags": "Int64",
    "Fwd Header Len": "Int64",
    "Bwd Header Len": "Int64",
    "Fwd Pkts/s": "float64",
    "Bwd Pkts/s": "float64",
    "Pkt Len Min": "Int64",
    "Pkt Len Max": "Int64",
    "Pkt Len Mean": "float64",
    "Pkt Len Std": "float64",
    "Pkt Len Var": "float64",
    "FIN Flag Cnt": "Int64",
    "SYN Flag Cnt": "Int64",
    "RST Flag Cnt": "Int64",
    "PSH Flag Cnt": "Int64",
    "ACK Flag Cnt": "Int64",
    "URG Flag Cnt": "Int64",
    "CWE Flag Count": "Int64",
    "ECE Flag Cnt": "Int64",
    "Down/Up Ratio": "Int64",
    "Pkt Size Avg": "float64",
    "Fwd Seg Size Avg": "float64",
    "Bwd Seg Size Avg": "float64",
    "Fwd Byts/b Avg": "Int64",
    "Fwd Pkts/b Avg": "Int64",
    "Fwd Blk Rate Avg": "Int64",
    "Bwd Byts/b Avg": "Int64",
    "Bwd Pkts/b Avg": "Int64",
    "Bwd Blk Rate Avg": "Int64",
    "Subflow Fwd Pkts": "Int64",
    "Subflow Fwd Byts": "Int64",
    "Subflow Bwd Pkts": "Int64",
    "Subflow Bwd Byts": "Int64",
    "Init Fwd Win Byts": "Int64",
    "Init Bwd Win Byts": "Int64",
    "Fwd Act Data Pkts": "Int64",
    "Fwd Seg Size Min": "Int64",
    "Active Mean": "float64",
    "Active Std": "float64",
    "Active Max": "Int64",
    "Active Min": "Int64",
    "Idle Mean": "float64",
    "Idle Std": "float64",
    "Idle Max": "Int64",
    "Idle Min": "Int64",
    "Label": "string",
}

if USE_SOURCE_DATA:
    MODEL_NAME += "_source_data"
    # load all csvs from the preprocessed data directory into a single dataframe
    logger.info("Loading preprocessed data...")

    if os.path.exists("training_data_source.csv"):
        dataset = pd.read_csv("training_data.csv")
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
                df = df[
                    not df.drop(["Timestamp", "Label"], axis=1).swifter.apply(
                        lambda x: x.astype(str).str.contains("Protocol").any(), axis=1
                    )
                ]
                
                logger.info("Converting data types...")
                # create any columns in DATA_TYPES.keys() that are missing
                # and fill them with NaN
                for col in DATA_TYPES.keys():
                    if col not in df.columns:
                        df[col] = np.nan

                # cast data types
                df = df.astype(DATA_TYPES)

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

target = "is_attack"
dropped_x_cols = ["date_minutes", "attack_type", "is_attack", "has_attack_ip"]
if USE_SOURCE_DATA:
    # if we're using preprocessed data, we need to select different columns
    target = "Label"
    # map target to binary 0 or 1 depending of if it's 'Benign' or something else
    dataset[target] = dataset[target].map(lambda x: 0 if x == "Benign" else 1)

    dropped_x_cols = [
        "Label",
        "Timestamp",
        "Dst Port",
        "Dst IP",
        "Src Port",
        "Src IP",
        "Flow ID",
    ]

# print the first few rows of the dataset
logger.info(dataset.head())

# print the count of each attack type
logger.info(dataset[target].value_counts())

Y = dataset[target]
X = dataset.drop(dropped_x_cols, axis=1)

# print columns we're using for X and Y
logger.info(f"X: {X.columns}")
logger.info(f"Y: {Y.name}")

# print the types of each column
logger.info(X.dtypes)
logger.info(Y.dtypes)

logger.info("Splitting the data into train, test sets...")
X_train, X_test, Y_train, Y_test = train_test_split(
    X, Y, test_size=0.2, random_state=42
)

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

        # perform cross-validation
        # i.e. traing the model on a subset of the data and testing it on the rest
        # this is done multiple times to get a more accurate estimate of the model's performance
        cv = xgb.cv(params=params, nfold=5, metrics="error", seed=42, dtrain=D_train)
        score_mean = cv["test-error-mean"].iloc[-1]
        score_std = cv["test-error-std"].iloc[-1]

        # Print the accuracy of the classifier
        logger.info(f"CV Error: {score_mean} (±{score_std})")
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

    # Tune the hyperparameters
    # i.e. find the best settings for the training algorithm
    xgb_bo = BayesianOptimization(run_with_params, params, verbose=0)

    xgb_bo.maximize(init_points=5, n_iter=25)

    logger.info("Best parameters found: ", xgb_bo.max["params"])
    logger.info("Training the model with the best parameters...")

    best_params = xgb_bo.max["params"]
    best_params["max_depth"] = int(best_params["max_depth"])
    best_params["num_parallel_tree"] = int(best_params["num_parallel_tree"])

    model_best = xgb.train(best_params, D_train, num_boost_round=10)

    logger.info("Model trained successfully!")

    logger.info("Saving the model...")

    # save model to ./models directory
    joblib.dump(model_best, f"models/{MODEL_NAME}.joblib")

# test the model
logger.info("Testing the model...")
predict_dmatrix = xgb.DMatrix(X_test)
prediction = model_best.predict(predict_dmatrix)
# convert prediction from continuous probabilities to binary values
prediction = np.where(prediction > 0.5, 1, 0)
logger.info("Accuracy: " + str(np.mean(prediction == Y_test)))
logger.info("\n" + classification_report(Y_test, prediction))
