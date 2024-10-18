import joblib
from loguru import logger
import xgboost as xgb
from sklearn.model_selection import (
    RepeatedStratifiedKFold,
    cross_val_score,
    train_test_split,
)
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from bayes_opt import BayesianOptimization
import numpy as np
import duckdb
import cupy as cp

USE_GPU = False

con = duckdb.connect(database="data/pcap_metadata.duckdb", read_only=True)

logger.info("Loading data from the duckdb database...")

# Load data
dataset = con.execute("SELECT * FROM merged_aggregated").df()
Y = dataset["is_attack"]
X = dataset.drop(["date_minutes", "attack_type", "is_attack", "has_attack_ip"], axis=1)

# print columns we're using for X and Y
logger.info(f"X: {X.columns}")
logger.info(f"Y: {Y.name}")

logger.info("Splitting the data into train, test sets...")
X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

if USE_GPU:
    X_train = cp.array(X_train)
    Y_train = cp.array(Y_train)
    X_test = cp.array(X_test)
    Y_test = cp.array(Y_test)

D_train = xgb.DMatrix(X_train, label=Y_train)
D_test = xgb.DMatrix(X_test, label=Y_test)

logger.info("Training the XGBoost classifier...")

def run_with_params(max_depth, gamma, learning_rate, n_estimators, subsample):
    """
        Run the XGBoost classifier with the given parameters
    """
    params = {
        'max_depth': int(max_depth),
        'gamma': gamma,
        'learning_rate':learning_rate,
        'subsample': subsample,
        'tree_method': 'hist',
        'num_parallel_tree': int(n_estimators),
        'device': 'cuda' if USE_GPU else 'cpu',
    }

    # perform cross-validation
    # i.e. traing the model on a subset of the data and testing it on the rest
    # this is done multiple times to get a more accurate estimate of the model's performance
    cv = xgb.cv(params=params, nfold=5, metrics='error', seed=42, dtrain=D_train)
    score_mean = cv['test-error-mean'].iloc[-1]
    score_std = cv['test-error-std'].iloc[-1]
    
    # Print the accuracy of the classifier
    logger.info(f"CV Error: {1 - score_mean} (±{score_std})")

    return score_mean

def test_model(test_model, test):
    """
        Tests the model using the test set
        Prints the classification report
    """
    logger.info("Testing the model...")
    prediction = test_model.predict(test)
    logger.info(classification_report(test, prediction))
    logger.info("Precision: ", precision_score(test, prediction))
    logger.info("Recall: ", recall_score(test, prediction))
    logger.info("F1 Score: ", f1_score(test, prediction))

params = {
    "max_depth": (1, 100),
    "gamma": (0, 1),
    "learning_rate": (0.01, 1),
    "subsample": (0.5, 1),
    "n_estimators": (50, 1000),
}

# Tune the hyperparameters
# i.e. find the best settings for the training algorithm
xgb_bo = BayesianOptimization(run_with_params, params)

results = xgb_bo.maximize(init_points=200, n_iter=20)

best_params = xgb_bo.max['params']
best_params['max_depth']= int(best_params['max_depth'])
best_params['n_estimators']= int(best_params['n_estimators'])

model_best = xgb.train(best_params, D_train, num_boost_round=10)

# since we now have the best model, we can test it
test_model(model_best, X_test)

# save model to ./models directory
joblib.dump(model_best, "models/xgboost_rf.joblib")
