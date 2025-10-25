# Projeto-Integrador-IV
Projeto Integrador IV: Sistema de detecção de phishing em textos com interface web


#app.py
import os
import json
from flask import Flask, request, render_template, jsonify
from flask_cors import CORS

app = Flask(__name__, template_folder="templates")
CORS(app)


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

def heuristic_detect(text: str):
    """Fallback heuristic classifier returning (label, explanation, score)."""
    text_lower = text.lower()
    suspicious_indicators = []
    score = 0
    keywords = ["click here", "verify", "account", "password", "bank", "urgent", "transfer", "login", "invoice", "link", "reset", "clique aqui", "verifique", "senha", "conta", "urgente", "transferência"]
    for k in keywords:
        if k in text_lower:
            suspicious_indicators.append(f"contém '{k}'")
            score += 1
    
    if "http://" in text_lower or "https://" in text_lower:
        suspicious_indicators.append("contém link(s) na mensagem")
        score += 1
    
    if any(w in text_lower for w in ["immediately", "agora", "urgente", "24 horas", "48 horas"]):
        suspicious_indicators.append("linguagem de urgência/imposição")
        score += 1

    
    if score >= 2:
        label = "Suspeito de Phishing"
    elif score >= 1:
        label = "Potencial risco - ver com atenção"
    else:
        label = "Provavelmente seguro"

    explanation = " | ".join(suspicious_indicators) if suspicious_indicators else "Nenhum indicativo claro detectado pelo heurístico."
    confidence = min(0.95, 0.2 + 0.2 * score)  # rough confidence
    return {"label": label, "explanation": explanation, "confidence": round(confidence, 2)}

def analyze_with_openai(text: str):
    try:
        import openai
        openai.api_key = OPENAI_API_KEY
        system_prompt = (
            "Você é um classificador de phishing. Recebe um e-mail/texto e retorna um JSON com "
            "chave 'label', 'explanation' (em pt-br) e 'confidence' (0-1). "
            "Se for phishing, explique os sinais principais."
        )
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Analise o texto abaixo e retorne apenas JSON:\n\n{text}"}
            ],
            max_tokens=300,
            temperature=0.0,
        )
        content = response.choices[0].message.content.strip()
        try:
            return json.loads(content)
        except Exception:
            return {"label": "Indeterminado", "explanation": content, "confidence": 0.5}
    except Exception as e:
        return {"error": str(e), **heuristic_detect(text)}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.json or {}
    text = data.get("text", "")
    if not text:
        return jsonify({"error": "Campo 'text' é obrigatório."}), 400

    if OPENAI_API_KEY:
        result = analyze_with_openai(text)
        if isinstance(result, dict) and result.get("error"):
            result = heuristic_detect(text)
            result["note"] = "Usando fallback heurístico (OpenAI falhou)."
    else:
        result = heuristic_detect(text)
        result["note"] = "Usando heurístico local (sem OPENAI_API_KEY)."

    return jsonify(result)

if __name__ == "__main__:
    app.run(debug=True, port=5000)


#Requirements.txt

Flask>=2.0
flask-cors
openai>=0.27.0


#README.md

#Detector de Phishing Inteligente - Protótipo (C2)

#Como rodar (Windows + VS Code)

1. Abra o terminal no VS Code (Terminal > New Terminal) na pasta do projeto.

2. Criar e ativar ambiente virtual:
   ```
   python -m venv venv
   .\venv\Scripts\Activate
   ```

3. Instalar dependências:
   ```
   pip install -r requirements.txt
   ```

4. (Opcional) Se tiver chave OpenAI e quiser usar:
   - No PowerShell:
     ```
     $env:OPENAI_API_KEY="sua_chave_aqui"
     ```

5. Rodar o servidor:
   ```
   python app.py
   ```

6. Abrir no navegador:
   ```
   http://localhost:5000
   ```

#Observações Técnicas
- Se não houver `OPENAI_API_KEY`, o sistema usa um heurístico local para demonstrar a lógica.
- Para C3: integrar com Gmail API, adicionar histórico de análises e aprimorar o modelo de classificação.


#Templates
 index.html

<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Detector de Phishing Inteligente - Protótipo</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 900px; margin: 2rem auto; padding: 1rem; }
    textarea { width: 100%; height: 180px; }
    button { padding: 10px 16px; margin-top: 8px; }
    .result { margin-top: 1rem; padding: 1rem; border: 1px solid #ddd; border-radius: 8px; }
    .label { font-weight: bold; font-size: 1.2rem; }
  </style>
</head>
<body>
  <h1>Detector de Phishing Inteligente (Protótipo)</h1>

  <label for="emailText">Cole aqui o texto do e-mail/mensagem:</label>
  <textarea id="emailText" placeholder="Cole um e-mail de exemplo..."></textarea>
  <br/>
  <button id="analyzeBtn">Analisar</button>

  <div id="loading" style="display:none">Analisando...</div>

  <div id="resultBox" class="result" style="display:none">
    <div class="label" id="label"></div>
    <div><strong>Confiança:</strong> <span id="confidence"></span></div>
    <div><strong>Explicação:</strong></div>
    <div id="explanation"></div>
    <div style="margin-top:8px;font-size:0.9rem;color:#666" id="note"></div>
  </div>

  <hr/>
  <p>Repositório: 
  <a href="https://github.com/nathanfaesa2025-sketch/Projeto-Integrador-IV" target="_blank">
    https://github.com/nathanfaesa2025-sketch/Projeto-Integrador-IV
  </a>
</p>


  <script src="/static/main.js"></script>
</body>
</html>

#Static
 main.js

 // static/main.js
document.addEventListener("DOMContentLoaded", () => {
  const analyzeBtn = document.getElementById("analyzeBtn");
  const emailText = document.getElementById("emailText");
  const resultBox = document.getElementById("resultBox");
  const labelEl = document.getElementById("label");
  const explanationEl = document.getElementById("explanation");
  const confidenceEl = document.getElementById("confidence");
  const loading = document.getElementById("loading");
  const noteEl = document.getElementById("note");

  analyzeBtn.addEventListener("click", async () => {
    const text = emailText.value.trim();
    if (!text) {
      alert("Cole um texto de e-mail/mensagem para analisar.");
      return;
    }
    loading.style.display = "block";
    resultBox.style.display = "none";
    try {
      const resp = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text })
      });
      const data = await resp.json();
      loading.style.display = "none";
      if (data.error) {
        alert("Erro: " + data.error);
        return;
      }
      labelEl.textContent = data.label || "Indeterminado";
      explanationEl.textContent = data.explanation || (data.message || "");
      confidenceEl.textContent = (data.confidence !== undefined) ? data.confidence : "—";
      noteEl.textContent = data.note ? data.note : "";
      resultBox.style.display = "block";
    } catch (err) {
      loading.style.display = "none";
      alert("Erro ao conectar com o backend: " + err.message);
    }
  });
});

#Documentação Não Técnica - Detector de Phishing Inteligente

#1. Objetivo do Projeto
O sistema "Detector de Phishing Inteligente" é um protótipo que permite aos usuários analisar textos de e-mails ou mensagens e identificar possíveis tentativas de phishing. Seu objetivo é fornecer uma análise rápida e intuitiva, ajudando usuários a detectar mensagens suspeitas e evitar golpes.

#2. Público-alvo
- Usuários comuns que desejam verificar a segurança de mensagens recebidas.
- Profissionais de TI e segurança da informação que precisam de um apoio rápido para triagem de e-mails suspeitos.
- Empresas que desejam conscientizar funcionários sobre tentativas de phishing.

#3. Funcionalidades Principais
- Analisar textos de e-mails ou mensagens e identificar risco de phishing.
- Classificação simples em três níveis: 
  - "Suspeito de Phishing"
  - "Potencial risco - ver com atenção"
  - "Provavelmente seguro"
- Explicação clara dos indícios que levaram à classificação.
- Indicador de confiança na análise.
- Interface web simples e intuitiva, que não exige conhecimento técnico.

#4. Benefícios
- Facilita a identificação de mensagens maliciosas.
- Reduz o risco de cair em golpes online.
- Permite aprendizado e conscientização sobre padrões de phishing.
- Ferramenta leve, que pode ser usada sem necessidade de instalação complexa.

#5. Fluxo de Uso
1. O usuário acessa o sistema pelo navegador.
2. Cola o texto do e-mail ou mensagem na área de análise.
3. Clica no botão "Analisar".
4. O sistema retorna:
   - Classificação do risco
   - Confiança da análise
   - Explicação dos sinais detectados
5. O usuário toma decisão baseada nas informações apresentadas.

#6. Observações
- Caso não haja chave OpenAI, o sistema utiliza um método heurístico simples.
- Futuras melhorias podem incluir integração com APIs de e-mail, histórico de análises e alertas automáticos.

#Documentação Técnica - Detector de Phishing Inteligente

#1. Visão Geral
O projeto consiste em um sistema web de detecção de phishing em textos, desenvolvido em Python com Flask no backend e HTML/JavaScript no frontend. Ele classifica mensagens como phishing ou seguras utilizando heurísticas e, opcionalmente, a API OpenAI GPT para análise avançada.

#2. Tecnologias Utilizadas
- Backend: Python, Flask
- Frontend: HTML, CSS, JavaScript
- Bibliotecas:
  - `flask-cors` (para permitir requisições cross-origin)
  - `openai` (opcional, para análise avançada de textos)
- Outras dependências: `json`, `os`

#3. Estrutura de Diretórios

Projeto-Integrador-IV/
│
├── app.py # Aplicação principal Flask
├── requirements.txt # Dependências do projeto
├── README.md # Instruções básicas
├── templates/ # HTML
│ └── index.html
├── static/ # JS e CSS
│ └── main.js
└── docs/ # Documentação
├── documentacao_tecnica.md
└── documentacao_nao_tecnica.md

#4. Endpoints do Sistema
- GET /  
  Renderiza a página principal (`index.html`).

- POST /api/analyze  
  Recebe JSON com a chave `"text"` contendo o texto da mensagem e retorna JSON com:
  ```json
  {
    "label": "Suspeito de Phishing",
    "explanation": "contém 'click here' | contém link(s) na mensagem",
    "confidence": 0.6,
    "note": "Usando heurístico local (sem OPENAI_API_KEY)"
  }
Caso OPENAI_API_KEY esteja configurada, utiliza a API OpenAI GPT-4o-mini.

Se ocorrer erro, fallback para heurística local.

#5. Fluxo de Dados
Usuário envia texto via frontend (formulário HTML + JS).

Backend Flask recebe a requisição.

O texto é analisado:

Heurística local: procura palavras-chave suspeitas, links e linguagem de urgência.

OpenAI GPT: classifica e retorna JSON detalhado.

Resultado é enviado ao frontend e exibido na interface.

#6. Heurística Local
Palavras-chave suspeitas: click here, verify, account, password, bank, urgent, transfer, etc.

Identificação de links (http:// ou https://)

Linguagem de urgência (immediately, agora, 24 horas, 48 horas)

Classificação baseada na quantidade de sinais detectados:

≥2 sinais → Suspeito de Phishing

1 sinal → Potencial risco

0 sinais → Provavelmente seguro

#7. Instalação e Execução

1.Criar ambiente virtual:
python -m venv venv
#Linux/Mac
source venv/bin/activate
#Windows
.\venv\Scripts\Activate
2.Instalar dependências:
pip install -r requirements.txt

3.Configurar OpenAI API Key (opcional):
#Linux/Mac
export OPENAI_API_KEY="sua_chave"
#Windows
setx OPENAI_API_KEY "sua_chave"

4.Rodar o servidor:
python app.py

5.Acessar via navegador:

http://localhost:5000
