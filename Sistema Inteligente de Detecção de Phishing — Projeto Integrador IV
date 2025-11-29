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

# Detector de Phishing Inteligente – MVP Entrega da C3

#app.py - Detector de Phishing Inteligente (MVP)
import os
import json
from datetime import datetime
from flask import Flask, request, render_template, jsonify
from flask_cors import CORS

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
HIST_FILE = "historico.txt"

def save_history(text, label, confidence):
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"{now} | {label} | {confidence} | {text.replace('\\n',' ')}\\n"
        with open(HIST_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception as e:
        print("Erro ao salvar histórico:", e)

def read_history(limit=20):
    if not os.path.exists(HIST_FILE):
        return []
    with open(HIST_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    lines = [l.strip() for l in lines if l.strip()]
    return lines[-limit:][::-1]

def heuristic_detect(text: str):
    text_lower = text.lower()
    suspicious = []
    score = 0

    keywords = ["clique aqui","click here","verifique","verificar","senha","password","conta","account","banco","bank","transferência","transfer","urgente","imediato","24 horas","48 horas","sua conta será","será desativada","suspensa","bloqueada","atualize seus dados","confirmar"]
    for k in keywords:
        if k in text_lower:
            suspicious.append(f"contém '{k}'")
            score += 1

    if "http://" in text_lower or "https://" in text_lower or "www." in text_lower:
        suspicious.append("contém link(s) na mensagem")
        score += 1

    shorteners = ["bit.ly","tinyurl","goo.gl","t.co","ow.ly"]
    if any(s in text_lower for s in shorteners):
        suspicious.append("contém link encurtado (pode ser suspeito)")
        score += 1

    sensitive = ["cpf","rg","senha","password","login","cartão","numero do cartão","cvv"]
    if any(s in text_lower for s in sensitive):
        suspicious.append("pede dados sensíveis")
        score += 1

    if ".zip" in text_lower or ".exe" in text_lower or ".scr" in text_lower:
        suspicious.append("anexo executável/comprimido suspeito")
        score += 1

    if any(w.upper() in text for w in ["URGENTE","IMEDIATO","ACTION REQUIRED"]):
        suspicious.append("linguagem de urgência (caixa alta)")
        score += 1

    domains = text_lower.count("http")
    if domains >= 2:
        suspicious.append("múltiplos links/dominios")
        score += 1

    if score >= 3:
        label = "Suspeito de Phishing"
    elif score == 2:
        label = "Potencial risco - ver com atenção"
    else:
        label = "Provavelmente seguro"

    explanation = " | ".join(suspicious) if suspicious else "Nenhum indicativo claro detectado pelo heurístico."
    confidence = min(0.98, 0.25 + 0.25 * score)
    return {"label": label, "explanation": explanation, "confidence": round(confidence,2)}

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
                {"role": "user", "content": f"Analise o texto abaixo e retorne apenas JSON:\\n\\n{text}"}
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

    # save history
    try:
        save_history(text, result.get("label","Indeterminado"), result.get("confidence",0))
    except Exception:
        pass

    return jsonify(result)

@app.route("/api/history", methods=["GET"])
def history():
    lines = read_history(50)
    return jsonify({"history": lines})

if __name__ == "__main__":
    app.run(debug=True, port=5000)



#requirements.txt

Flask>=2.0
flask-cors
openai>=0.27.0
pillow

#templates/index.html

<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Detector de Phishing Inteligente - MVP</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
  <style>
    :root{
      --primary:#3B82F6;
      --green:#10B981;
      --yellow:#F59E0B;
      --red:#EF4444;
      --bg:#f6f9ff;
      --card:#ffffff;
      --muted:#6b7280;
    }
    *{box-sizing:border-box}
    body{font-family:Inter, Arial, sans-serif;background:var(--bg);margin:0;padding:32px}
    .container{max-width:1100px;margin:0 auto}
    header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
    h1{color:#0f172a;margin:0;font-size:28px}
    .subtitle{color:var(--muted);font-size:14px}
    .card{background:var(--card);border-radius:12px;padding:18px;box-shadow:0 6px 18px rgba(15,23,42,0.06);margin-bottom:16px}
    textarea{width:100%;height:180px;border-radius:8px;border:1px solid #e6eefc;padding:12px;font-size:14px;resize:vertical}
    .row{display:flex;gap:12px;align-items:center}
    .btn{background:var(--primary);color:white;padding:10px 14px;border:none;border-radius:8px;cursor:pointer;font-weight:600}
    .btn.ghost{background:transparent;color:var(--primary);border:1px solid rgba(59,130,246,0.12)}
    .result-area{margin-top:14px}
    .result-card{border-radius:10px;padding:14px}
    .label{font-weight:700;font-size:18px;margin-bottom:6px}
    .explain{color:var(--muted);margin-top:8px;white-space:pre-wrap}
    .controls{display:flex;justify-content:space-between;align-items:center;margin-top:8px}
    .history-list{max-height:220px;overflow:auto;margin-top:10px;padding:8px;border-radius:8px;background:#fbfdff;border:1px solid #eef6ff}
    .pill{display:inline-block;padding:6px 10px;border-radius:999px;font-weight:600}
    .pill.safe{background:rgba(16,185,129,0.12);color:var(--green)}
    .pill.warn{background:rgba(245,158,11,0.12);color:var(--yellow)}
    .pill.danger{background:rgba(239,68,68,0.08);color:var(--red)}
    footer{color:var(--muted);font-size:13px;margin-top:18px}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>Detector de Phishing Inteligente (MVP)</h1>
        <div class="subtitle">Protótipo melhorado </div>
      </div>
      <div>
        <button id="viewHistory" class="btn ghost">Ver Histórico</button>
      </div>
    </header>

    <div class="card">
      <label for="emailText"><strong>Cole o texto do e-mail/mensagem:</strong></label>
      <textarea id="emailText" placeholder="Cole um e-mail de exemplo..."></textarea>
      <div class="controls">
        <div style="display:flex;gap:8px">
          <button id="analyzeBtn" class="btn">Analisar</button>
          <button id="clearBtn" class="btn ghost">Limpar</button>
        </div>
        <div style="color:var(--muted);font-size:13px"> </div>
      </div>

      <div id="resultArea" class="result-area" style="display:none">
        <div id="resultCard" class="card result-card"></div>
      </div>
    </div>

    <div class="card">
      <h3>Histórico (últimas análises)</h3>
      <div id="history" class="history-list">Nenhuma análise ainda.</div>
    </div>

    <footer>
      Repositório:
<a href="https://github.com/nathanfaesa2025-sketch/Projeto-Integrador-IV" target="_blank">
    https://github.com/nathanfaesa2025-sketch/Projeto-Integrador-IV
</a>
 

    </footer>
  </div>

  <script src="/static/main.js"></script>
</body>
</html>

#static

// main.js - interações do MVP
document.addEventListener('DOMContentLoaded', ()=> {
  const analyzeBtn = document.getElementById('analyzeBtn');
  const emailText = document.getElementById('emailText');
  const resultArea = document.getElementById('resultArea');
  const resultCard = document.getElementById('resultCard');
  const clearBtn = document.getElementById('clearBtn');
  const historyDiv = document.getElementById('history');
  const viewHistoryBtn = document.getElementById('viewHistory');

  async function fetchHistory(){
    try{
      const r = await fetch('/api/history');
      const j = await r.json();
      const list = j.history || [];
      if(list.length === 0){
        historyDiv.textContent = 'Nenhuma análise ainda.';
        return;
      }
      historyDiv.innerHTML = '';
      list.forEach(item=>{
        const el = document.createElement('div');
        el.style.padding = '6px 8px';
        el.style.borderBottom = '1px solid #eef6ff';
        el.style.fontSize = '13px';
        el.textContent = item;
        historyDiv.appendChild(el);
      });
    }catch(e){
      historyDiv.textContent = 'Erro ao carregar histórico.';
    }
  }

  function makePill(label){
    const span = document.createElement('span');
    span.className = 'pill';
    if(label.toLowerCase().includes('phishing') || label.toLowerCase().includes('suspeito')){
      span.classList.add('danger'); span.style.background='rgba(239,68,68,0.08)'; span.style.color='#ef4444';
      span.textContent = label;
    } else if(label.toLowerCase().includes('potencial')){
      span.classList.add('warn'); span.style.background='rgba(245,158,11,0.12)'; span.style.color='#f59e0b';
      span.textContent = label;
    } else {
      span.classList.add('safe'); span.style.background='rgba(16,185,129,0.12)'; span.style.color='#10b981';
      span.textContent = label;
    }
    return span;
  }

  analyzeBtn.addEventListener('click', async ()=>{
    const text = emailText.value.trim();
    if(!text){ alert('Cole um texto para analisar.'); return; }
    resultArea.style.display = 'block';
    resultCard.innerHTML = '<div style="color:#6b7280">Analisando...</div>';
    try{
      const resp = await fetch('/api/analyze', {
        method:'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({text})
      });
      const data = await resp.json();
      if(data.error){ resultCard.innerHTML = '<div style="color:#ef4444">Erro: '+data.error+'</div>'; return; }
      const label = data.label || 'Indeterminado';
      const conf = (data.confidence !== undefined)? data.confidence : '—';
      const explanation = data.explanation || '';
      // build card
      resultCard.innerHTML = '';
      const top = document.createElement('div');
      top.style.display='flex'; top.style.justifyContent='space-between'; top.style.alignItems='center';
      const left = document.createElement('div');
      const pill = makePill(label);
      left.appendChild(pill);
      const confEl = document.createElement('div');
      confEl.style.fontSize='13px'; confEl.style.color='#6b7280'; confEl.style.marginTop='8px';
      confEl.textContent = 'Confiança: ' + conf;
      left.appendChild(confEl);
      top.appendChild(left);
      resultCard.appendChild(top);
      const expl = document.createElement('div');
      expl.className='explain';
      expl.textContent = explanation;
      resultCard.appendChild(expl);
      if(data.note){
        const note = document.createElement('div'); note.style.marginTop='8px'; note.style.fontSize='12px'; note.style.color='#6b7280';
        note.textContent = data.note;
        resultCard.appendChild(note);
      }
      // refresh history
      await fetchHistory();
    }catch(e){
      resultCard.innerHTML = '<div style="color:#ef4444">Erro ao conectar com o backend.</div>';
    }
  });

  clearBtn.addEventListener('click', ()=>{ emailText.value=''; resultArea.style.display='none'; });

  viewHistoryBtn.addEventListener('click', async ()=>{ await fetchHistory(); window.scrollTo({top:document.body.scrollHeight, behavior:'smooth'}); });

  // load history on start
  fetchHistory();
});

#docs

#documentacao_tecnica.md
1. Visão Geral

Este projeto é um protótipo web (MVP) desenvolvido em Python + Flask que realiza análise de textos para identificar possíveis mensagens de phishing.
Ele utiliza duas formas de análise:

Heurística Local (funciona sem internet e sem chave de API)

Análise via OpenAI (opcional — caso o usuário configure uma chave OPENAI_API_KEY)

O sistema recebe um texto, analisa e retorna:

Classificação (Suspeito / Risco Moderado / Provavelmente Seguro)

Explicação dos sinais detectados

Nível de confiança

Histórico das últimas análises

2. Estrutura do Projeto
detector-phishing/
│ app.py
│ historico.txt
│ demo_inputs.txt
│ README.md
│ requirements.txt
│
├── templates/
│   └── index.html
└── static/
    └── main.js

3. Arquivos e Funções Principais
   app.py

Arquivo principal do backend.

Responsável por:

Inicializar o Flask

Receber requisições

Analisar textos

Salvar histórico

Retornar resultados ao frontend

Rotas principais:

Rota	Método	Função
/	GET	Carrega a interface gráfica
/api/analyze	POST	Analisa o texto enviado pelo usuário
/api/history	GET	Retorna o histórico das análises


4. Mecanismo de Análise (Heurística Local)

Função central: heuristic_detect(text)

Ela procura sinais como:

links suspeitos: http://, https://, www.

encurtadores: bit.ly, tinyurl, t.co

palavras-chave maliciosas
"senha", "urgente", "confirme", "verify", "account", "bank", "transfer", "invoice"

pedidos de dados sensíveis
"cpf", "rg", "cartão", "cvv"

anexos executáveis
.zip, .exe, .scr

uso de letras maiúsculas (indício de urgência)

Sistema de Pontuação

Cada sinal encontrado vale 1 ponto.

Classificação:

Score	Classificação
3 ou mais	Suspeito de Phishing
2	Potencial Risco — Veja com Atenção
0 ou 1	Provavelmente Seguro
 Confiança

Gerada assim:

confidence = min(0.98, 0.25 + score * 0.25)


5. Análise com OpenAI (Opcional)

Função: analyze_with_openai(text)

Só roda caso exista a variável de ambiente OPENAI_API_KEY.

Envia o texto para a IA.

Pede como resposta um JSON com:

label

explanation

confidence

Se houver erro → cai automaticamente para a heurística local.


6. Histórico (historico.txt)

Cada análise é registrada assim:

2025-11-28 21:05:33 | Suspeito de Phishing | 0.81 | "texto analisado..."


O frontend carrega somente as últimas 20 entradas.



7. Frontend (index.html + main.js)
index.html

Container principal do MVP

Campo de texto

Botão Analisar

Botão Limpar

Link para Ver Histórico

Painel com resultados

Área exibindo o histórico

main.js

Responsável por:

Enviar texto para /api/analyze

Exibir resultado na tela

Atualizar histórico

Aplicar tema visual (tema azul do MVP C3)


8. Instalação e Execução
1 Criar ambiente virtual

Windows:

python -m venv venv
.\venv\Scripts\activate


Linux/macOS:

python3 -m venv venv
source venv/bin/activate

2 Instalar dependências
pip install -r requirements.txt

3 (Opcional) Configurar chave OpenAI
setx OPENAI_API_KEY "SUA_CHAVE_AQUI"

4 Rodar o servidor
python app.py

5 Acessar no navegador
http://localhost:5000



9. Endpoints da API
POST /api/analyze

Envio:

{
  "text": "Olá, clique aqui para confirmar sua conta..."
}


Retorno:

{
  "label": "Suspeito de Phishing",
  "explanation": "contém link suspeito | palavras de urgência",
  "confidence": 0.82
}

GET /api/history

Retorno:

{
  "history": [
    "2025-11-28 21:12:01 | Potencial risco | 0.55 | ..."
  ]
}


10. Segurança e Considerações

Flask está em modo debug → NÃO usar em produção.

OpenAI só deve ser ativado com chave protegida.

O sistema não substitui análises humanas de segurança.

Histórico fica salvo localmente no arquivo.


11. Possíveis Melhorias

Criar um modelo de Machine Learning próprio.

Implementar detecção semântica avançada.

Adicionar login e dashboard com métricas.

Criar API REST completa com autenticação.

Fazer deploy com Nginx + Gunicorn.


#Documentação Não Técnica — Detector de Phishing Inteligente (MVP)

##1. Visão Geral
O Detector de Phishing Inteligente é um protótipo web que permite ao usuário colar o texto de um e-mail ou mensagem e receber uma classificação de risco (Suspeito de Phishing / Potencial risco / Provavelmente seguro), uma explicação dos sinais detectados e um indicador de confiança. O objetivo é ajudar pessoas e empresas a identificar mensagens maliciosas de forma rápida.

##2. Público-alvo
- Usuários finais (colaboradores de empresas, público em geral) que desejam verificar se uma mensagem é segura.
- Profissionais de TI e segurança que precisam de uma triagem rápida.
- Professores e alunos para demonstração de técnicas de detecção de phishing.

##3. Funcionalidades principais
- Campo para colar texto de e-mail/mensagem.
- Classificação automática do risco.
- Explicação dos motivos (por exemplo: contém link, pede CPF, linguagem de urgência).
- Indicador de confiança (valor entre 0 e 1).
- Histórico local das últimas análises (arquivo `historico.txt`).
- Suporte opcional a API da OpenAI para análises mais sofisticadas (se configurada).

##4. Fluxo de uso (simples)
1. Abrir o site (http://localhost:5000).  
2. Colar o texto do e-mail/mensagem no campo.  
3. Clicar em *Analisar*.  
4. Visualizar a classificação, explicação e confiança.  
5. Consultar o histórico de análises (na página).

##5. Benefícios e limitações
*Benefícios*
- Rápido e simples de usar.
- Ajuda a conscientizar usuários sobre sinais de phishing.
- Funciona offline sem chave de API (heurística local).

*Limitações*
- Heurística simples pode gerar falsos positivos/negativos.
- Análises automáticas não substituem investigação humana em casos críticos.
- Uso da OpenAI (quando habilitada) depende de chave e política de privacidade.

##6. O que apresentar no vídeo da Entrega 3
- Mostrar o servidor rodando (`python app.py`).  
- Acessar `http://localhost:5000`.  
- Demonstrar 3 exemplos (phishing claro, suspeito, seguro).  
- Mostrar o histórico atualizando.  
- Mostrar o repositório GitHub e o README.

---

#demo_inputs.txt

1 PHISHING CLARO
Prezado cliente, sua conta será desativada em 24 horas. 
Clique aqui http://bank-verificacao-alerta.com/login para confirmar seus dados imediatamente.

2 SUSPEITO MODERADO
Olá, identificamos uma atividade incomum. 
Responda este e-mail informando seu CPF e data de nascimento para continuar usando sua conta.

3 MENSAGEM SEGURA
Olá João, segue em anexo o relatório solicitado da reunião de terça-feira. 
Qualquer dúvida, estou à disposição.


#historico.txt
2025-11-28 22:08:52 | Suspeito de Phishing | 0.98 | Prezado cliente, sua conta será desativada em 24 horas. Clique aqui http://fake-bank.example/reset para verificar suas credenciais. Atenciosamente, Equipe Bank.\n2025-11-28 22:12:24 | Suspeito de Phishing | 0.98 | Olá, detectamos uma tentativa de login na sua conta. Para confirmar, responda este e-mail com seu número de CPF e senha para evitarmos o bloqueio.\n2025-11-28 22:12:37 | Provavelmente seguro | 0.25 | Olá João, segue o resumo do relatório solicitado. Abra o anexo quando tiver tempo. Atenciosamente, Maria (rh@empresa.com)\n2025-11-28 22:13:36 | Potencial risco - ver com atenção | 0.75 | Atenção! Seu cartão de crédito foi temporariamente bloqueado. Para evitar a cobrança de taxas, faça a verificação imediata acessando: https://secure-validacao-payments.info. 
Confirme seus dados pessoais e o número do seu cartão para restaurar o acesso.\n2025-11-28 22:13:46 | Suspeito de Phishing | 0.98 | Olá, precisamos atualizar algumas informações do seu cadastro. 
Por favor, envie seu CPF e a foto do seu documento para continuarmos o atendimento.
Isso evita que sua conta seja suspensa.\n2025-11-28 22:13:48 | Suspeito de Phishing | 0.98 | Olá, precisamos atualizar algumas informações do seu cadastro. 
Por favor, envie seu CPF e a foto do seu documento para continuarmos o atendimento.
Isso evita que sua conta seja suspensa.\n2025-11-28 22:13:57 | Provavelmente seguro | 0.25 | Boa tarde! 
Segue o link para a reunião de amanhã e o documento com as anotações da última conversa.
Qualquer dúvida, estou à disposição.
Abraços, Fernanda.\n2025-11-28 23:30:57 | Suspeito de Phishing | 0.98 | Prezado cliente, sua conta será desativada em 24 horas. 
Clique aqui http://bank-verificacao-alerta.com/login para confirmar seus dados imediatamente.\n2025-11-28 23:34:34 | Suspeito de Phishing | 0.98 | Prezado cliente, sua conta será desativada em 24 horas. 
Clique aqui http://bank-verificacao-alerta.com/login para confirmar seus dados imediatamente.\n2025-11-28 23:35:52 | Suspeito de Phishing | 0.98 | Prezado cliente, sua conta será desativada em 24 horas. 
Clique aqui http://bank-verificacao-alerta.com/login para confirmar seus dados imediatamente.\n2025-11-28 23:36:06 | Potencial risco - ver com atenção | 0.75 | Olá, identificamos uma atividade incomum. 
Responda este e-mail informando seu CPF e data de nascimento para continuar usando sua conta.\n2025-11-28 23:36:23 | Provavelmente seguro | 0.25 | Olá João, segue em anexo o relatório solicitado da reunião de terça-feira. 

