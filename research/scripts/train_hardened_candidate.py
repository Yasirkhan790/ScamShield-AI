from pathlib import Path
import hashlib
import json
import platform

import joblib
import numpy as np
import pandas as pd
import sklearn

from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)


# ============================================================
# PATHS
# ============================================================

SPLIT_DIR = Path(
    "research/data/splits"
)

MODEL_DIR = Path(
    "research/models"
)

REPORT_DIR = Path(
    "research/reports"
)

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


MODEL_VERSION = (
    "scamshield-text-v2-hardened-candidate-2"
)

# Reviewed hardening examples receive slightly more influence
# than one ordinary dataset row.
HARDENING_SAMPLE_WEIGHT = 4.0


# ============================================================
# TRAINING-ONLY HARDENING DATA
#
# These are NOT copies of the challenge sentences.
# They are generic examples based on the ScamShield taxonomy.
#
# Validation and test sets are never modified.
# ============================================================

HARDENING_EXAMPLES = [

    # ========================================================
    # 1. VERIFICATION CODE / OTP / SECURITY CODE REQUESTS
    # ========================================================

    (
        "Send me the security digits that appeared "
        "in the message on your phone.",
        "scam",
    ),

    (
        "Reply with the temporary verification number "
        "you received on your mobile.",
        "scam",
    ),

    (
        "Please provide the six digit authentication "
        "number sent to your device.",
        "scam",
    ),

    (
        "Forward the security code from the latest "
        "SMS so we can unlock your profile.",
        "scam",
    ),

    (
        "Tell us the confirmation number that was "
        "delivered to your phone.",
        "scam",
    ),

    (
        "Send the numeric code you just received "
        "so your identity can be verified.",
        "scam",
    ),

    (
        "We need the temporary access digits "
        "sent to your mobile before restoring the account.",
        "scam",
    ),

    (
        "Reply with the login verification number "
        "from the message on your phone.",
        "scam",
    ),

    (
        "Give me the authentication digits "
        "that arrived by text message.",
        "scam",
    ),

    (
        "Provide the security number sent to "
        "your registered mobile device.",
        "scam",
    ),

    (
        "Your account cannot be restored until "
        "you send the verification digits.",
        "scam",
    ),

    (
        "Read the one time security number "
        "from your phone and send it here.",
        "scam",
    ),

    (
        "Send the confirmation code from your "
        "latest security notification.",
        "scam",
    ),

    (
        "Share the temporary number generated "
        "for your login verification.",
        "scam",
    ),

    (
        "We require the security digits delivered "
        "to your phone to complete verification.",
        "scam",
    ),

    (
        "Forward the authentication number "
        "you received by SMS.",
        "scam",
    ),

    (
        "Tell the support agent the code "
        "that appeared on your mobile.",
        "scam",
    ),

    (
        "Please send the temporary login number "
        "so we can reactivate your account.",
        "scam",
    ),

    (
        "Give us the verification digits sent "
        "to your phone immediately.",
        "scam",
    ),

    (
        "Send the phone security code so your "
        "banking access can be restored.",
        "scam",
    ),


    # ========================================================
    # 2. PRIZE / REWARD + FEE SCAMS
    # ========================================================

    (
        "You have won a cash bonus. "
        "Pay the processing charge before it can be released.",
        "scam",
    ),

    (
        "Your prize is ready for collection. "
        "Send the claim fee before receiving the money.",
        "scam",
    ),

    (
        "Congratulations, a reward has been reserved "
        "for you. Pay the handling charge first.",
        "scam",
    ),

    (
        "Your lottery winnings have been approved. "
        "A release payment is required before transfer.",
        "scam",
    ),

    (
        "You are the selected winner of a cash promotion. "
        "Pay the activation fee to receive your reward.",
        "scam",
    ),

    (
        "A large reward is waiting in your name. "
        "Send a small processing payment to claim it.",
        "scam",
    ),

    (
        "Your cash award is ready. "
        "Pay the transfer charge before the funds can be sent.",
        "scam",
    ),

    (
        "You have received an unexpected prize. "
        "The delivery fee must be paid before release.",
        "scam",
    ),

    (
        "Your winning payment is on hold until "
        "you pay the administrative fee.",
        "scam",
    ),

    (
        "Claim your reward by paying the required "
        "verification charge today.",
        "scam",
    ),

    (
        "A promotional cash prize has been assigned "
        "to you. Pay the release cost first.",
        "scam",
    ),

    (
        "Your giveaway reward has been approved. "
        "Submit the processing payment to collect it.",
        "scam",
    ),

    (
        "You won a large cash amount. "
        "A small clearance fee is required before withdrawal.",
        "scam",
    ),

    (
        "The prize department has approved your reward. "
        "Send the claim charge to receive the funds.",
        "scam",
    ),

    (
        "Your reward payment cannot be released "
        "until the activation charge is paid.",
        "scam",
    ),


    # ========================================================
    # 3. JOB / RECRUITMENT FEE SCAMS
    # ========================================================

    (
        "You have been selected for a remote job "
        "without an interview. Pay the registration charge.",
        "scam",
    ),

    (
        "Start working from home immediately after "
        "sending the application fee.",
        "scam",
    ),

    (
        "Your employment is guaranteed. "
        "Pay the training payment before starting.",
        "scam",
    ),

    (
        "No interview is needed for this position. "
        "Send the onboarding fee today.",
        "scam",
    ),

    (
        "We have approved you for a home based job. "
        "Pay the registration cost to activate your account.",
        "scam",
    ),

    (
        "You are hired immediately. "
        "Transfer the recruitment fee to confirm your position.",
        "scam",
    ),

    (
        "Guaranteed employment is available after "
        "you pay the application charge.",
        "scam",
    ),

    (
        "Your job placement has been confirmed. "
        "Send the processing fee before joining.",
        "scam",
    ),

    (
        "Earn money from home with no interview. "
        "Pay the membership fee to begin.",
        "scam",
    ),

    (
        "Your remote work account will be activated "
        "after the registration payment.",
        "scam",
    ),

    (
        "The company has accepted you without an interview. "
        "Pay the training fee before receiving assignments.",
        "scam",
    ),

    (
        "A guaranteed job is available today. "
        "Submit the application payment immediately.",
        "scam",
    ),

    (
        "You have been chosen for online work. "
        "Pay an upfront registration fee before joining.",
        "scam",
    ),

    (
        "Your work from home position is confirmed. "
        "Send the onboarding payment to start.",
        "scam",
    ),

    (
        "There is no interview for this job. "
        "Pay the enrollment fee to receive your tasks.",
        "scam",
    ),


    # ========================================================
    # OTHER IMPORTANT SCAM BEHAVIORS
    # ========================================================

    (
        "Your account has been restricted. "
        "Send your username and password to restore access.",
        "scam",
    ),

    (
        "Your bank access will be disabled unless "
        "you provide your login information.",
        "scam",
    ),

    (
        "We detected unusual activity. "
        "Reply with your password for verification.",
        "scam",
    ),

    (
        "Double your money within one week "
        "with absolutely no investment risk.",
        "scam",
    ),

    (
        "Guaranteed profit is available if you "
        "deposit money into this investment today.",
        "scam",
    ),

    (
        "This trading opportunity guarantees "
        "large returns with no possibility of loss.",
        "scam",
    ),

    (
        "Buy gift cards and send us the card numbers "
        "to complete your payment.",
        "scam",
    ),

    (
        "Send cryptocurrency to this wallet "
        "to unlock your pending funds.",
        "scam",
    ),

    (
        "Your parcel cannot be delivered until "
        "you pay the redelivery charge.",
        "scam",
    ),

    (
        "Install this remote access application "
        "so support can control your computer.",
        "scam",
    ),

    (
        "Disable your antivirus and install "
        "the attached program to restore access.",
        "scam",
    ),

    (
        "Send your identity card and bank statement "
        "to receive the unexpected payment.",
        "scam",
    ),


    # ========================================================
    # LEGITIMATE SECURITY / MITIGATING EXAMPLES
    #
    # These are important so words such as OTP, security code,
    # password, prize and job do not automatically mean scam.
    # ========================================================

    (
        "Never share a security code received "
        "on your phone with another person.",
        "legitimate",
    ),

    (
        "A genuine bank employee should never ask "
        "for your one time verification number.",
        "legitimate",
    ),

    (
        "Keep the six digit security code private "
        "and do not send it to anyone.",
        "legitimate",
    ),

    (
        "The verification number sent to your phone "
        "is for your use only.",
        "legitimate",
    ),

    (
        "Do not give your password or authentication "
        "code to another person.",
        "legitimate",
    ),

    (
        "Our support team will never request "
        "your password, PIN or verification code.",
        "legitimate",
    ),

    (
        "If anyone requests the security digits "
        "sent to your mobile, end the conversation.",
        "legitimate",
    ),

    (
        "Use the official banking application "
        "to manage security settings.",
        "legitimate",
    ),

    (
        "Contact the bank through its official number "
        "if someone asks for login credentials.",
        "legitimate",
    ),

    (
        "Security reminder: never disclose "
        "your account password.",
        "legitimate",
    ),

    (
        "A legitimate prize should not require "
        "an upfront release payment.",
        "legitimate",
    ),

    (
        "Be cautious if someone says you won "
        "a reward and then requests a fee.",
        "legitimate",
    ),

    (
        "Our company never charges candidates "
        "a registration fee for employment.",
        "legitimate",
    ),

    (
        "Job applicants should never send money "
        "to recruiters to secure a position.",
        "legitimate",
    ),

    (
        "Verify a recruiter through the company's "
        "official website before sharing information.",
        "legitimate",
    ),

    (
        "A real employer normally does not require "
        "payment before an interview.",
        "legitimate",
    ),


    # ========================================================
    # NORMAL BENIGN EXAMPLES
    # ========================================================

    (
        "Our meeting has been scheduled "
        "for ten tomorrow morning.",
        "legitimate",
    ),

    (
        "The team meeting will take place "
        "in the conference room tomorrow.",
        "legitimate",
    ),

    (
        "Your monthly statement is available "
        "inside the official banking application.",
        "legitimate",
    ),

    (
        "Your salary payment was deposited "
        "into your account today.",
        "legitimate",
    ),

    (
        "Your appointment has been confirmed "
        "for Monday afternoon.",
        "legitimate",
    ),

    (
        "The lecture room has changed "
        "for tomorrow's class.",
        "legitimate",
    ),

    (
        "Your order has been dispatched "
        "and can be tracked in the official application.",
        "legitimate",
    ),

    (
        "The project report has been uploaded "
        "to the shared folder.",
        "legitimate",
    ),

    (
        "Please review the document "
        "before the team discussion.",
        "legitimate",
    ),

    (
        "Your payment receipt is available "
        "inside your account dashboard.",
        "legitimate",
    ),
]


# ============================================================
# LOAD SPLITS
# ============================================================

def load_split(name):

    path = (
        SPLIT_DIR /
        f"{name}.csv"
    )

    df = pd.read_csv(
        path,
        low_memory=False,
    )

    df = df.dropna(
        subset=[
            "text",
            "label",
        ]
    ).copy()

    df["text"] = (
        df["text"]
        .astype(str)
        .str.strip()
    )

    return df


# ============================================================
# BUILD HARDENING DATAFRAME
# ============================================================

def build_hardening_dataframe():

    records = []

    for index, (
        text,
        label,
    ) in enumerate(
        HARDENING_EXAMPLES,
        start=1,
    ):

        records.append(
            {
                "record_id":
                    f"hardening-v2-{index:04d}",

                "text":
                    text,

                "label":
                    label,

                "category":
                    "manual_hardening",

                "language":
                    "en",

                "indicators":
                    "",

                "source":
                    "manual_taxonomy_hardening_v2",

                "source_label":
                    label,

                "label_quality":
                    "strong",

                "source_type":
                    "manual",

                "is_synthetic":
                    True,

                "review_status":
                    "reviewed",

                "notes":
                    (
                        "Training-only taxonomy-driven "
                        "hardening example"
                    ),
            }
        )

    return pd.DataFrame(
        records
    )


# ============================================================
# MODEL
# ============================================================

def build_model():

    word_features = TfidfVectorizer(
        lowercase=True,

        ngram_range=(
            1,
            3,
        ),

        min_df=2,

        max_df=0.995,

        max_features=35000,

        sublinear_tf=True,

        strip_accents="unicode",
    )

    char_features = TfidfVectorizer(
        analyzer="char_wb",

        lowercase=True,

        ngram_range=(
            3,
            6,
        ),

        min_df=2,

        max_features=30000,

        sublinear_tf=True,

        strip_accents="unicode",
    )

    features = FeatureUnion(
        [
            (
                "word_tfidf",
                word_features,
            ),

            (
                "char_tfidf",
                char_features,
            ),
        ]
    )

    classifier = LogisticRegression(
        max_iter=1500,

        class_weight="balanced",

        solver="liblinear",

        C=2.0,

        random_state=42,
    )

    return Pipeline(
        [
            (
                "features",
                features,
            ),

            (
                "classifier",
                classifier,
            ),
        ]
    )


# ============================================================
# MODEL SCORE
# ============================================================

def get_scam_scores(
    model,
    texts,
):

    probabilities = (
        model.predict_proba(
            texts
        )
    )

    classes = list(
        model.classes_
    )

    scam_index = (
        classes.index(
            "scam"
        )
    )

    return probabilities[
        :,
        scam_index,
    ]


# ============================================================
# METRICS
# ============================================================

def calculate_metrics(
    labels,
    scores,
    threshold,
):

    actual = (
        labels == "scam"
    ).astype(
        int
    )

    predicted = (
        scores >= threshold
    ).astype(
        int
    )

    matrix = confusion_matrix(
        actual,
        predicted,
        labels=[
            0,
            1,
        ],
    )

    tn, fp, fn, tp = (
        matrix.ravel()
    )

    return {
        "threshold":
            float(
                threshold
            ),

        "accuracy":
            float(
                accuracy_score(
                    actual,
                    predicted,
                )
            ),

        "precision_scam":
            float(
                precision_score(
                    actual,
                    predicted,
                    zero_division=0,
                )
            ),

        "recall_scam":
            float(
                recall_score(
                    actual,
                    predicted,
                    zero_division=0,
                )
            ),

        "f1_scam":
            float(
                f1_score(
                    actual,
                    predicted,
                    zero_division=0,
                )
            ),

        "true_negative":
            int(
                tn
            ),

        "false_positive":
            int(
                fp
            ),

        "false_negative":
            int(
                fn
            ),

        "true_positive":
            int(
                tp
            ),
    }


# ============================================================
# THRESHOLD TUNING
# VALIDATION SET ONLY
# ============================================================

def tune_threshold(
    labels,
    scores,
):

    print(
        "\nTuning threshold using VALIDATION ONLY..."
    )

    rows = []

    thresholds = np.arange(
        0.10,
        0.901,
        0.01,
    )

    for threshold in thresholds:

        metrics = (
            calculate_metrics(
                labels,
                scores,
                threshold,
            )
        )

        rows.append(
            metrics
        )

    result_df = pd.DataFrame(
        rows
    )

    result_df.to_csv(
        REPORT_DIR /
        "hardened_candidate_v2_threshold_sweep.csv",

        index=False,
    )

    eligible = result_df[
        result_df[
            "recall_scam"
        ]
        >= 0.85
    ].copy()

    if not eligible.empty:

        eligible = (
            eligible.sort_values(
                by=[
                    "f1_scam",
                    "precision_scam",
                    "recall_scam",
                ],

                ascending=[
                    False,
                    False,
                    False,
                ],
            )
        )

        selected = (
            eligible.iloc[
                0
            ]
        )

        reason = (
            "Highest validation F1 among thresholds "
            "with validation scam recall >= 0.85"
        )

    else:

        result_df = (
            result_df.sort_values(
                by=[
                    "f1_scam",
                    "recall_scam",
                ],

                ascending=[
                    False,
                    False,
                ],
            )
        )

        selected = (
            result_df.iloc[
                0
            ]
        )

        reason = (
            "No validation threshold reached recall 0.85. "
            "Highest validation F1 selected."
        )

    return (
        float(
            selected[
                "threshold"
            ]
        ),
        reason,
    )


# ============================================================
# SHA256
# ============================================================

def sha256_file(path):

    hasher = hashlib.sha256()

    with open(
        path,
        "rb",
    ) as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            hasher.update(
                chunk
            )

    return hasher.hexdigest()


# ============================================================
# PRINT METRICS
# ============================================================

def print_metrics(
    title,
    metrics,
):

    print(
        "\n"
        + "=" * 65
    )

    print(
        title
    )

    print(
        "=" * 65
    )

    print(
        "Threshold:",
        f"{metrics['threshold']:.2f}",
    )

    print(
        "Accuracy:",
        f"{metrics['accuracy']:.4f}",
    )

    print(
        "Precision:",
        f"{metrics['precision_scam']:.4f}",
    )

    print(
        "Recall:",
        f"{metrics['recall_scam']:.4f}",
    )

    print(
        "F1:",
        f"{metrics['f1_scam']:.4f}",
    )

    print(
        "\nConfusion matrix:"
    )

    print(
        "TN:",
        metrics[
            "true_negative"
        ],
    )

    print(
        "FP:",
        metrics[
            "false_positive"
        ],
    )

    print(
        "FN:",
        metrics[
            "false_negative"
        ],
    )

    print(
        "TP:",
        metrics[
            "true_positive"
        ],
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 65
    )

    print(
        "ScamShield AI V2 - Hardened Candidate V2"
    )

    print(
        "=" * 65
    )

    train_df = load_split(
        "train"
    )

    validation_df = load_split(
        "validation"
    )

    test_df = load_split(
        "test"
    )

    hardening_df = (
        build_hardening_dataframe()
    )

    print(
        "\nOriginal train records:",
        len(
            train_df
        ),
    )

    print(
        "Hardening records:",
        len(
            hardening_df
        ),
    )

    # ========================================================
    # PROTECT VALIDATION + TEST
    # ========================================================

    protected_text = set(
        pd.concat(
            [
                validation_df[
                    "text"
                ],

                test_df[
                    "text"
                ],
            ]
        )
        .astype(
            str
        )
        .str.casefold()
        .str.strip()
    )

    hardening_df[
        "_compare"
    ] = (
        hardening_df[
            "text"
        ]
        .astype(
            str
        )
        .str.casefold()
        .str.strip()
    )

    before = len(
        hardening_df
    )

    hardening_df = (
        hardening_df[
            ~hardening_df[
                "_compare"
            ]
            .isin(
                protected_text
            )
        ]
        .copy()
    )

    hardening_df = (
        hardening_df.drop(
            columns=[
                "_compare"
            ]
        )
    )

    removed = (
        before
        - len(
            hardening_df
        )
    )

    print(
        "Hardening examples removed due to "
        "validation/test exact overlap:",
        removed,
    )

    # ========================================================
    # TRAINING DATA
    # ========================================================

    augmented_train = (
        pd.concat(
            [
                train_df,
                hardening_df,
            ],

            ignore_index=True,

            sort=False,
        )
    )

    # Original records weight = 1
    # Reviewed hardening examples weight = 4
    sample_weights = np.concatenate(
        [
            np.ones(
                len(
                    train_df
                ),
                dtype=float,
            ),

            np.full(
                len(
                    hardening_df
                ),
                HARDENING_SAMPLE_WEIGHT,
                dtype=float,
            ),
        ]
    )

    print(
        "\nFinal training records:",
        len(
            augmented_train
        ),
    )

    print(
        "Hardening sample weight:",
        HARDENING_SAMPLE_WEIGHT,
    )

    print(
        "\nTraining labels:"
    )

    print(
        augmented_train[
            "label"
        ]
        .value_counts()
    )

    # ========================================================
    # TRAIN
    # ========================================================

    model = build_model()

    print(
        "\nTraining hardened candidate V2..."
    )

    model.fit(
        augmented_train[
            "text"
        ],

        augmented_train[
            "label"
        ],

        classifier__sample_weight=
            sample_weights,
    )

    print(
        "Training completed."
    )

    # ========================================================
    # VALIDATION
    # ========================================================

    validation_scores = (
        get_scam_scores(
            model,

            validation_df[
                "text"
            ],
        )
    )

    (
        threshold,
        threshold_reason,
    ) = tune_threshold(
        validation_df[
            "label"
        ],

        validation_scores,
    )

    validation_metrics = (
        calculate_metrics(
            validation_df[
                "label"
            ],

            validation_scores,

            threshold,
        )
    )

    print_metrics(
        "VALIDATION RESULTS",
        validation_metrics,
    )

    print(
        "\nThreshold selection:"
    )

    print(
        threshold_reason
    )

    # ========================================================
    # EXISTING TEST
    #
    # Comparison only.
    # We have already looked at this test set.
    # ========================================================

    test_scores = (
        get_scam_scores(
            model,

            test_df[
                "text"
            ],
        )
    )

    comparison_metrics = (
        calculate_metrics(
            test_df[
                "label"
            ],

            test_scores,

            threshold,
        )
    )

    print_metrics(
        "COMPARISON TEST RESULTS",
        comparison_metrics,
    )

    print(
        "\nNOTE:"
    )

    print(
        "These test metrics are comparison-only. "
        "They are NOT the final untouched release metrics."
    )

    # ========================================================
    # SAVE CANDIDATE
    # ========================================================

    model_path = (
        MODEL_DIR /
        "scamshield_text_model_candidate.joblib"
    )

    joblib.dump(
        model,
        model_path,
    )

    model_hash = (
        sha256_file(
            model_path
        )
    )

    metadata = {
        "release_status":
            "candidate",

        "model_version":
            MODEL_VERSION,

        "model_type":
            (
                "word_char_tfidf_"
                "logistic_regression_hardened_v2"
            ),

        "selected_threshold":
            threshold,

        "threshold_selection":
            threshold_reason,

        "base_train_records":
            len(
                train_df
            ),

        "hardening_records":
            len(
                hardening_df
            ),

        "hardening_sample_weight":
            HARDENING_SAMPLE_WEIGHT,

        "final_train_records":
            len(
                augmented_train
            ),

        "validation_records":
            len(
                validation_df
            ),

        "comparison_test_records":
            len(
                test_df
            ),

        "validation_metrics":
            validation_metrics,

        "comparison_test_metrics":
            comparison_metrics,

        "targeted_hardening_families": [
            "verification_code_request",
            "prize_fee_scam",
            "job_fee_scam",
            "security_advice_mitigation",
        ],

        "comparison_test_warning":
            (
                "Existing test split has already been "
                "used during development. Final release "
                "requires a fresh holdout."
            ),

        "python_version":
            platform.python_version(),

        "scikit_learn_version":
            sklearn.__version__,

        "pandas_version":
            pd.__version__,

        "numpy_version":
            np.__version__,

        "joblib_version":
            joblib.__version__,

        "model_sha256":
            model_hash,

        "score_warning":
            (
                "model_scam_score is supporting model evidence "
                "and is not a verified real-world fraud probability"
            ),
    }

    metadata_path = (
        MODEL_DIR /
        "scamshield_text_model_candidate.metadata.json"
    )

    metadata_path.write_text(
        json.dumps(
            metadata,
            indent=2,
        ),

        encoding="utf-8",
    )

    print(
        "\n"
        + "=" * 65
    )

    print(
        "HARDENED CANDIDATE V2 CREATED"
    )

    print(
        "=" * 65
    )

    print(
        "\nModel:"
    )

    print(
        model_path
    )

    print(
        "\nMetadata:"
    )

    print(
        metadata_path
    )

    print(
        "\nSHA-256:"
    )

    print(
        model_hash
    )

    print(
        "\nValidation-selected threshold:"
    )

    print(
        round(
            threshold,
            4,
        )
    )


if __name__ == "__main__":
    main()