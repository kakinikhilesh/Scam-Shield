# 🛡️ ScamShield AI
### AI-Powered SMS, Phishing Email, and Fake Job Scam Detection

## Project Overview

ScamShield AI is a machine learning-based web application designed to identify potentially fraudulent messages, including SMS scams, phishing emails, and fake job offers.

The system uses a fine-tuned **DistilBERT** transformer model combined with rule-based safety checks to analyze user-submitted text and identify suspicious content.

## Key Features

- SMS scam detection
- Phishing email detection
- Fake job offer scam detection
- Detection of suspicious job registration fees
- Detection of requests for OTPs, passwords, and UPI PINs
- Banking transaction context review
- AI scam score and safety warnings
- Interactive Flask-based web interface

## Technologies Used

| Component | Technology |
|---|---|
| Programming language | Python |
| Deep learning framework | PyTorch |
| NLP model | DistilBERT |
| Model library | Hugging Face Transformers |
| Backend | Flask |
| Frontend | HTML, CSS, JavaScript |
| Data processing | Pandas |

## System Architecture

1. User enters an SMS, email, or job-related message.
2. The Flask backend receives the text.
3. The DistilBERT tokenizer processes the input.
4. The fine-tuned model predicts whether the message is legitimate or potentially fraudulent.
5. Rule-based safety checks identify additional suspicious indicators.
6. Banking context checks identify transaction-style notifications requiring review.
7. The website displays the final result, model scam score, and safety warnings.

## Dataset

The model was trained using a combined dataset containing examples of legitimate and fraudulent messages from multiple categories, including SMS, phishing emails, and job postings.

Additional examples were incorporated to improve the model's coverage of fake job offers and SMS phishing.

## Model Training

The project uses a fine-tuned DistilBERT sequence classification model.

- Classification labels: 0 = Legitimate, 1 = Scam
- Maximum input length: 256 tokens
- Training framework: PyTorch and Hugging Face Transformers
- Improved model directory: `scamshield_distilbert_improved`

## Model Evaluation

The improved DistilBERT model achieved the following results on the project's validation dataset:

| Metric | Result |
|---|---|
| Accuracy | 98.87% |
| Precision | 98.99% |
| Recall | 98.01% |
| F1-score | 98.50% |

These results describe the validation dataset and do not guarantee equivalent performance on new, real-world messages. The combined rule-based system requires separate evaluation.

## Running the Application

### 1. Activate the virtual environment

From the main project directory, run:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 2. Start the Flask server

```powershell
python .\ScamShield_Web\app.py
```

### 3. Open the website

Visit:

`http://127.0.0.1:5000`

### 4. Analyze a message

Paste an SMS, email, or job offer into the text box and click **Analyze Message**.

The website displays one of three results:

- **Potential Scam:** The model classified the message as a scam.
- **Suspicious - Review Required:** Additional safety checks identified concerns, or a banking notification needs verification.
- **Likely Legitimate:** The model classified the message as legitimate and no safety rule was triggered.

## Limitations

- The model can produce false positives and false negatives.
- Only the first 256 tokens of each message are analyzed by DistilBERT.
- Rule-based checks cannot identify every type of scam.
- Banking context review does not authenticate the sender.
- The displayed model score is not a guarantee of real-world scam probability.
- The application is a prototype and should not replace independent verification.

## Future Enhancements

- Improve model performance on legitimate banking notifications.
- Expand the diversity of scam and legitimate message examples.
- Evaluate the complete hybrid system on a separate test dataset.
- Improve model handling of long messages.
- Enhance the web interface and deployment process.

## Disclaimer

ScamShield AI is an educational project intended to assist users in identifying potentially suspicious messages. Predictions may be incorrect. Users should independently verify sensitive financial, employment, or account-related communications through trusted official channels.