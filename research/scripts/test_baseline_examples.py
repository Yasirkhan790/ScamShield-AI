from pathlib import Path

import joblib


MODEL_PATH = Path(
    "research/models/scamshield_baseline.joblib"
)


TEST_MESSAGES = [
    "Send your OTP immediately to verify your account.",

    "Tell me the six-digit number that was just sent to your mobile.",

    "Forward the security code you received so we can restore your access.",

    "Please provide the confirmation digits sent by SMS.",

    "Never share your OTP or password with anyone.",

    "Your salary has been deposited successfully.",

    "Congratulations. You have won a cash reward. Pay the release charge to claim it.",

    "A small activation payment is required before your reward can be transferred.",

    "We detected unusual activity. Open the link and confirm your login information.",

    "Your monthly bank statement is now available in the official mobile app.",
]


def main():

    model = joblib.load(
        MODEL_PATH
    )

    for message in TEST_MESSAGES:

        prediction = model.predict(
            [message]
        )[0]

        probabilities = (
            model.predict_proba(
                [message]
            )[0]
        )

        classes = (
            model.classes_
        )

        scores = dict(
            zip(
                classes,
                probabilities,
            )
        )

        scam_probability = (
            scores.get(
                "scam",
                0.0,
            )
        )

        print(
            "\n"
            + "=" * 70
        )

        print(
            f"Message: {message}"
        )

        print(
            f"Prediction: {prediction}"
        )

        print(
            "Scam probability: "
            f"{scam_probability:.4f}"
        )


if __name__ == "__main__":
    main()