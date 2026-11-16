FROM python:3.13-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Retrain inside the image so the model always matches the installed scikit-learn,
# and refuse to build if any test fails.
RUN python -m contauth.ml.train && python -m pytest -q tests && rm -rf instance
ENV CA_DATABASE=/srv/instance/contauth.db
EXPOSE 8000
# Hosts like Render pass the port in $PORT. --preload loads the app (and its secret
# key) once, before the workers fork.
CMD gunicorn --preload -w 2 --timeout 60 -b 0.0.0.0:${PORT:-8000} "contauth:create_app()"
