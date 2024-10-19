import joblib
from loguru import logger
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score
import xgboost as xgb
from sklearn.model_selection import (
    train_test_split,
)
from bayes_opt import BayesianOptimization
import numpy as np
import duckdb
import pandas as pd
import os

THREADS = 35
MODEL_NAME = "xgboost_rf"
USE_SOURCE_DATA = True
SOURCE_DATA_DIR = "/home/nlaha/storage"

if USE_SOURCE_DATA:
    MODEL_NAME += "_source_data"
    # load all csvs from the preprocessed data directory into a single dataframe
    logger.info("Loading preprocessed data...")
    dataset = pd.concat(
        [pd.read_csv(f"{SOURCE_DATA_DIR}/Processed Traffic Data for ML Algorithms/{file}", header=0) 
         for file in os.listdir(f"{SOURCE_DATA_DIR}/Processed Traffic Data for ML Algorithms")], ignore_index=True
    )
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
    # set datatype of all used columns
    dataset = dataset.astype({
        "Protocol": "int32",
        "Flow Duration": "int32",
        "Tot Fwd Pkts": "int32",
        "Tot Bwd Pkts": "int32",
        "TotLen Fwd Pkts": "int32",
        "TotLen Bwd Pkts": "int32",
        "Fwd Pkt Len Max": "int32",
        "Fwd Pkt Len Min": "int32",
        "Fwd Pkt Len Mean": "float64",
        "Fwd Pkt Len Std": "float64",
        "Bwd Pkt Len Max": "int32",
        "Bwd Pkt Len Min": "int32",
        "Bwd Pkt Len Mean": "float64",
        "Bwd Pkt Len Std": "float64",
        "Flow Byts/s": "float64",
        "Flow Pkts/s": "float64",
        "Flow IAT Mean": "float64",
        "Flow IAT Std": "float64",
        "Flow IAT Max": "int32",
        "Flow IAT Min": "int32",
        "Fwd IAT Tot": "int32",
        "Fwd IAT Mean": "float64",
        "Fwd IAT Std": "float64",
        "Fwd IAT Max": "int32",
        "Fwd IAT Min": "int32",
        "Bwd IAT Tot": "int32",
        "Bwd IAT Mean": "float64",
        "Bwd IAT Std": "float64",
        "Bwd IAT Max": "int32",
        "Bwd IAT Min": "int32",
        "Fwd PSH Flags": "int32",
        "Bwd PSH Flags": "int32",
        "Fwd URG Flags": "int32",
        "Bwd URG Flags": "int32",
        "Fwd Header Len": "int32",
        "Bwd Header Len": "int32",
        "Fwd Pkts/s": "float64",
        "Bwd Pkts/s": "float64",
        "Pkt Len Min": "int32",
        "Pkt Len Max": "int32",
        "Pkt Len Mean": "float64",
        "Pkt Len Std": "float64",
        "Pkt Len Var": "float64",
        "FIN Flag Cnt": "int32",
        "SYN Flag Cnt": "int32",
        "RST Flag Cnt": "int32",
        "PSH Flag Cnt": "int32",
        "ACK Flag Cnt": "int32",
        "URG Flag Cnt": "int32",
        "CWE Flag Count": "int32",
        "ECE Flag Cnt": "int32",
        "Down/Up Ratio": "int32",
        "Pkt Size Avg": "float64",
        "Fwd Seg Size Avg": "float64",
        "Bwd Seg Size Avg": "float64",
        "Fwd Byts/b Avg": "int32",
        "Fwd Pkts/b Avg": "int32",
        "Fwd Blk Rate Avg": "int32",
        "Bwd Byts/b Avg": "int32",
        "Bwd Pkts/b Avg": "int32",
        "Bwd Blk Rate Avg": "int32",
        "Subflow Fwd Pkts": "int32",
        "Subflow Fwd Byts": "int32",
        "Subflow Bwd Pkts": "int32",
        "Subflow Bwd Byts": "int32",
        "Init Fwd Win Byts": "int32",
        "Init Bwd Win Byts": "int32",
        "Fwd Act Data Pkts": "int32",
        "Fwd Seg Size Min": "int32",
        "Active Mean": "float64",
        "Active Std": "float64",
        "Active Max": "int32",
        "Active Min": "int32",
        "Idle Mean": "float64",
        "Idle Std": "float64",
        "Idle Max": "int32",
        "Idle Min": "int32",
    })
    
    # make label boolean
    dataset["Label"] = dataset["Label"].map(lambda x: 0 if x == "Benign" else 1)
        
    dropped_x_cols = ["Label", "Timestamp", "Dst Port", "Dst IP", "Src Port", "Src IP", "Flow ID"]

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
X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

D_train = xgb.DMatrix(X_train, label=Y_train)
D_test = xgb.DMatrix(X_test, label=Y_test)

# check to see if we have a model saved
if os.path.exists(f"models/{MODEL_NAME}.joblib"):
    logger.info("Model already trained, loading it from file...")
    model_best = joblib.load(f"models/{MODEL_NAME}.joblib")
    logger.info("Model loaded successfully!")
else:
    logger.info("Training the XGBoost classifier...")

    def run_with_params(max_depth, gamma, learning_rate, num_parallel_tree, subsample, colsample_bynode):
        """
            Run the XGBoost classifier with the given parameters
        """
        params = {
            'max_depth': int(max_depth),
            'gamma': gamma,
            'learning_rate':learning_rate,
            'subsample': subsample,
            'tree_method': 'hist',
            'num_parallel_tree': int(num_parallel_tree),
            'colsample_bynode': colsample_bynode,
            'nthread': THREADS,
            'objective': 'binary:logistic',
        }

        # perform cross-validation
        # i.e. traing the model on a subset of the data and testing it on the rest
        # this is done multiple times to get a more accurate estimate of the model's performance
        cv = xgb.cv(params=params, nfold=5, metrics='error', seed=42, dtrain=D_train)
        score_mean = cv['test-error-mean'].iloc[-1]
        score_std = cv['test-error-std'].iloc[-1]
        
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

    logger.info("Best parameters found: ", xgb_bo.max['params'])
    logger.info("Training the model with the best parameters...")

    best_params = xgb_bo.max['params']
    best_params['max_depth']= int(best_params['max_depth'])
    best_params['num_parallel_tree']= int(best_params['num_parallel_tree'])

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