from django.shortcuts import render
from django.views.decorators.csrf import csrf_protect
import os
import joblib
from .analysis import analyze_threats

# Ruta base de la app
APP_DIR = os.path.dirname(os.path.abspath(__file__))

# Ruta al modelo
MODEL_PATH = os.path.join(APP_DIR, "ml_models", "phishing_text_model.joblib")

# Cargar el modelo entrenado
model = joblib.load(MODEL_PATH)

MODEL_INFO = "Random Forest (best F1-score on validation set)"

# Umbral manual de probabilidad para marcar como phishing
THRESHOLD = 0.63  # 60% de confianza mínima


@csrf_protect
def index(request):
    subject = ""
    sender = ""
    body = ""
    prediction = None      # "Phishing" o "Legitimate"
    probability = None     # 0–100 (float)
    threats = []

    if request.method == "POST":
        subject = request.POST.get("subject", "")
        sender = request.POST.get("sender", "")
        body = request.POST.get("body", "")

        # Texto que ve el modelo (similar a tu versión original)
        input_text = body.strip()

        # Texto completo para el análisis de amenazas
        full_text = f"{subject}\nFrom: {sender}\n\n{body}".strip()

        if input_text:
            # --- PROBABILIDAD DE LA CLASE "1" (phishing) DE FORMA SEGURA ---
            classes = list(model.classes_)  # por ejemplo [0, 1]
            try:
                idx_phishing = classes.index(1)
            except ValueError:
                # Si por alguna razón no está la clase 1, usamos el último índice
                idx_phishing = -1

            proba_vector = model.predict_proba([input_text])[0]
            probability_value = float(proba_vector[idx_phishing])

            # Guardamos porcentaje para mostrar
            probability = round(probability_value * 100, 2)

            # Umbral manual
            if probability_value >= THRESHOLD:
                prediction = "Phishing"
            else:
                prediction = "Legitimate"

            # --- ANÁLISIS DE AMENAZAS ---
            raw_threats = analyze_threats(full_text)

            normalized_threats = []
            if isinstance(raw_threats, dict):
                raw_threats = [raw_threats]

            if isinstance(raw_threats, list):
                for t in raw_threats:
                    if isinstance(t, dict):
                        t_type = t.get("type", "Threat")
                        # En analysis.py usas "details"
                        details = t.get("details", "")
                        normalized_threats.append({
                            "type": t_type,
                            "detail": details,
                        })
                    else:
                        normalized_threats.append({
                            "type": "Threat",
                            "detail": str(t),
                        })

            threats = normalized_threats

    context = {
        "subject": subject,
        "sender": sender,
        "body": body,
        "prediction": prediction,
        "probability": probability,
        "model_info": MODEL_INFO,
        "threats": threats,
    }

    return render(request, "detector/index.html", context)
