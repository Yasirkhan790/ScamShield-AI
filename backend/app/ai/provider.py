class GeminiProvider(BaseAIProvider):
    name = "gemini"

    def __init__(self, api_key: str, model: str, base_url: str, timeout: float):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _post(self, payload: dict) -> dict:
        try:
            response = httpx.post(
                f"{self.base_url}/models/{self.model}:generateContent",
                params={"key": self.api_key},
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=self.timeout,
            )

            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            response_text = exc.response.text[:800]

            raise AIProviderError(
                f"Gemini request failed with HTTP {status_code}: {response_text}"
            ) from exc

        except httpx.TimeoutException as exc:
            raise AIProviderError(
                f"Gemini request timed out after {self.timeout} seconds"
            ) from exc

        except httpx.RequestError as exc:
            raise AIProviderError(
                f"Gemini network request failed: {exc}"
            ) from exc

        except (TypeError, ValueError) as exc:
            raise AIProviderError(
                f"Gemini response processing failed: {exc}"
            ) from exc

    def generate_json(self, user_prompt: str) -> str:
        payload = {
            "system_instruction": {
                "parts": [{"text": SCAMSHIELD_SYSTEM_PROMPT}]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}],
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        }

        try:
            data = self._post(payload)
            return data["candidates"][0]["content"]["parts"][0]["text"]

        except (KeyError, IndexError, TypeError) as exc:
            raise AIProviderError(
                f"Gemini provider returned an invalid response: {data}"
            ) from exc

    def extract_text_from_image(
        self,
        image_bytes: bytes,
        mime_type: str,
    ) -> str:
        encoded = base64.b64encode(image_bytes).decode("ascii")

        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": IMAGE_EXTRACTION_PROMPT
                        },
                        {
                            "inline_data": {
                                "mime_type": mime_type,
                                "data": encoded,
                            }
                        },
                    ],
                }
            ],
            "generationConfig": {
                "temperature": 0,
            },
        }

        try:
            data = self._post(payload)

            candidates = data.get("candidates", [])

            if not candidates:
                raise AIProviderError(
                    f"Gemini returned no candidates: {data}"
                )

            parts = (
                candidates[0]
                .get("content", {})
                .get("parts", [])
            )

            if not parts:
                raise AIProviderError(
                    f"Gemini returned no content parts: {data}"
                )

            text_parts = [
                str(part.get("text", ""))
                for part in parts
                if isinstance(part, dict)
            ]

            extracted_text = "\n".join(text_parts).strip()

            if not extracted_text:
                raise AIProviderError(
                    f"Gemini returned an empty text result: {data}"
                )

            return extracted_text

        except AIProviderError:
            raise

        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise AIProviderError(
                f"Gemini image extraction returned an invalid response: {exc}"
            ) from exc