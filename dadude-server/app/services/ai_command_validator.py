"""
AI Command Validator Service - NUOVO MODULO
Validazione comandi switch/router usando Claude AI
Analizza comandi per errori di sintassi, comandi pericolosi, best practices

Non modifica servizi esistenti
Richiede ANTHROPIC_API_KEY in environment
"""
import os
import logging
from typing import Dict, Any, List, Optional
import json

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


class AICommandValidator:
    """
    Validatore comandi di rete usando Claude AI
    Fornisce analisi avanzata di comandi per switch HP/Aruba e router MikroTik
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)

        # API key da config o environment
        self.api_key = self.config.get('anthropic_api_key') or os.getenv('ANTHROPIC_API_KEY')

        if not ANTHROPIC_AVAILABLE:
            self.logger.warning("anthropic package not installed. AI validation disabled.")
            self.enabled = False
        elif not self.api_key:
            self.logger.warning("ANTHROPIC_API_KEY not configured. AI validation disabled.")
            self.enabled = False
        else:
            self.client = anthropic.Anthropic(api_key=self.api_key)
            self.enabled = True
            self.logger.info("AI Command Validator initialized")

        # Modello da usare
        self.model = self.config.get('model', 'claude-3-5-sonnet-20241022')

    def validate_commands(
        self,
        commands: List[str],
        device_type: str,
        device_model: Optional[str] = None,
        context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Valida lista comandi usando Claude AI

        Args:
            commands: Lista comandi da validare
            device_type: "hp_aruba" o "mikrotik"
            device_model: Modello device (opzionale, per validazione specifica)
            context: Contesto aggiuntivo (es: "configurazione VLAN", "setup PoE")

        Returns:
            dict: {
                "valid": bool,
                "risk_level": str (low/medium/high/critical),
                "errors": list[dict],
                "warnings": list[dict],
                "suggestions": list[str],
                "analysis": str
            }
        """
        if not self.enabled:
            return self._disabled_response()

        try:
            # Costruisci prompt
            prompt = self._build_validation_prompt(
                commands=commands,
                device_type=device_type,
                device_model=device_model,
                context=context
            )

            # Chiama Claude API
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                temperature=0,
                system=self._get_system_prompt(device_type),
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )

            # Parse response
            analysis_text = response.content[0].text

            # Estrai struttura JSON dalla risposta
            result = self._parse_validation_response(analysis_text)

            self.logger.info(f"AI validation completed. Risk: {result.get('risk_level')}")

            return result

        except Exception as e:
            self.logger.error(f"AI validation failed: {e}", exc_info=True)
            return {
                "valid": None,
                "error": str(e),
                "fallback": True
            }

    def explain_command(
        self,
        command: str,
        device_type: str
    ) -> Dict[str, Any]:
        """
        Spiega cosa fa un comando specifico

        Returns:
            dict: {
                "command": str,
                "explanation": str,
                "impact": str,
                "reversible": bool,
                "suggested_precautions": list
            }
        """
        if not self.enabled:
            return {"error": "AI validation not available"}

        try:
            prompt = f"""Spiega cosa fa questo comando su un device {device_type}:

Comando: {command}

Fornisci:
1. Spiegazione dettagliata
2. Impatto sulla configurazione
3. Se è reversibile
4. Precauzioni suggerite

Rispondi in JSON con formato:
{{
    "explanation": "...",
    "impact": "...",
    "reversible": true/false,
    "suggested_precautions": ["..."]
}}
"""

            response = self.client.messages.create(
                model=self.model,
                max_tokens=1000,
                temperature=0,
                system=self._get_system_prompt(device_type),
                messages=[{"role": "user", "content": prompt}]
            )

            explanation_text = response.content[0].text

            # Parse JSON
            result = self._extract_json_from_text(explanation_text)
            result["command"] = command

            return result

        except Exception as e:
            self.logger.error(f"Command explanation failed: {e}", exc_info=True)
            return {"error": str(e)}

    def suggest_improvements(
        self,
        commands: List[str],
        device_type: str,
        goal: str
    ) -> Dict[str, Any]:
        """
        Suggerisce miglioramenti ai comandi per raggiungere un obiettivo

        Args:
            commands: Comandi attuali
            device_type: Tipo device
            goal: Obiettivo desiderato (es: "configurare VLAN 100 su porte 1-24")

        Returns:
            dict con suggerimenti miglioramenti
        """
        if not self.enabled:
            return {"error": "AI validation not available"}

        try:
            commands_text = "\n".join(commands)

            prompt = f"""Obiettivo: {goal}

Comandi attuali per device {device_type}:
```
{commands_text}
```

Analizza questi comandi e suggerisci:
1. Errori o problemi
2. Comandi mancanti
3. Ottimizzazioni
4. Best practices non seguite

Fornisci risposta in JSON:
{{
    "issues": ["..."],
    "missing_commands": ["..."],
    "optimizations": ["..."],
    "improved_commands": ["..."]
}}
"""

            response = self.client.messages.create(
                model=self.model,
                max_tokens=1500,
                temperature=0,
                system=self._get_system_prompt(device_type),
                messages=[{"role": "user", "content": prompt}]
            )

            suggestions_text = response.content[0].text
            result = self._extract_json_from_text(suggestions_text)

            return result

        except Exception as e:
            self.logger.error(f"Suggestion generation failed: {e}", exc_info=True)
            return {"error": str(e)}

    # ========================================================================
    # METODI PRIVATI
    # ========================================================================

    def _get_system_prompt(self, device_type: str) -> str:
        """Restituisce system prompt per tipo device"""
        if device_type == "hp_aruba":
            return """Sei un esperto di switch HP ProCurve e Aruba.
Conosci perfettamente la sintassi dei comandi, le best practices, e i potenziali rischi.
Quando validi comandi, sei preciso e dettagliato.
Identifichi comandi pericolosi (reload, erase, boot, delete) e configurazioni rischiose.
Fornisci sempre risposte in formato JSON strutturato."""

        elif device_type == "mikrotik":
            return """Sei un esperto di router MikroTik RouterOS.
Conosci perfettamente la sintassi dei comandi RouterOS, le best practices, e i potenziali rischi.
Quando validi comandi, sei preciso e dettagliato.
Identifichi comandi pericolosi e configurazioni rischiose.
Fornisci sempre risposte in formato JSON strutturato."""

        else:
            return """Sei un esperto di networking e configurazione dispositivi di rete.
Fornisci sempre risposte in formato JSON strutturato."""

    def _build_validation_prompt(
        self,
        commands: List[str],
        device_type: str,
        device_model: Optional[str],
        context: Optional[str]
    ) -> str:
        """Costruisce prompt per validazione"""
        commands_text = "\n".join([f"{i+1}. {cmd}" for i, cmd in enumerate(commands)])

        prompt = f"""Valida questi comandi per un device {device_type}"""

        if device_model:
            prompt += f" (modello: {device_model})"

        if context:
            prompt += f"\nContesto: {context}"

        prompt += f"""

Comandi da validare:
```
{commands_text}
```

Analizza e fornisci:
1. Validità generale (valid: true/false)
2. Livello di rischio (risk_level: low/medium/high/critical)
3. Lista errori di sintassi (errors: [{{command_index, error_type, description}}])
4. Lista warning (warnings: [{{command_index, warning_type, description}}])
5. Suggerimenti (suggestions: [string])
6. Analisi generale (analysis: string)

IMPORTANTE: Identifica comandi pericolosi come:
- HP/Aruba: reload, boot, erase, delete, format, no spanning-tree
- MikroTik: /system reset-configuration, /file remove, /system reboot

Rispondi SOLO in formato JSON:
{{
    "valid": boolean,
    "risk_level": "low|medium|high|critical",
    "errors": [
        {{
            "command_index": number,
            "command": "...",
            "error_type": "...",
            "description": "..."
        }}
    ],
    "warnings": [
        {{
            "command_index": number,
            "command": "...",
            "warning_type": "...",
            "description": "..."
        }}
    ],
    "suggestions": ["..."],
    "analysis": "..."
}}
"""
        return prompt

    def _parse_validation_response(self, text: str) -> Dict[str, Any]:
        """Parse risposta AI in struttura dati"""
        try:
            # Estrai JSON dalla risposta
            result = self._extract_json_from_text(text)

            # Validazione struttura
            if not isinstance(result, dict):
                raise ValueError("Response is not a dict")

            # Defaults
            result.setdefault("valid", False)
            result.setdefault("risk_level", "unknown")
            result.setdefault("errors", [])
            result.setdefault("warnings", [])
            result.setdefault("suggestions", [])
            result.setdefault("analysis", "")

            return result

        except Exception as e:
            self.logger.error(f"Failed to parse AI response: {e}")
            return {
                "valid": False,
                "error": "Failed to parse AI response",
                "raw_response": text
            }

    def _extract_json_from_text(self, text: str) -> Dict[str, Any]:
        """Estrae JSON da testo (anche se contiene markdown o altro)"""
        # Rimuovi markdown code blocks se presenti
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]

        # Parse JSON
        return json.loads(text.strip())

    def _disabled_response(self) -> Dict[str, Any]:
        """Risposta quando AI validation è disabilitata"""
        return {
            "valid": None,
            "enabled": False,
            "message": "AI validation not available. Install anthropic package and configure ANTHROPIC_API_KEY."
        }
