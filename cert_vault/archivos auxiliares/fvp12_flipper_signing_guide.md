# FVP12 PDF Signing With Flipper Approval

Version corta:

- `tools/fvp12_flipper_signing_quickstart.md`

## Objetivo

Este flujo permite firmar un PDF desde una pagina web local, pero dejando la aprobacion final en el Flipper Zero.

El PC hace la parte pesada:

- lee el bundle `.fvp12` desde el Flipper o desde una ruta local si quieres mantener compatibilidad
- descifra el bundle
- prepara la solicitud de firma
- firma el PDF con `pyHanko`
- devuelve el PDF firmado al navegador

El Flipper hace la aprobacion:

- detecta solicitudes pendientes
- muestra la primera solicitud disponible en `Cert Vault`
- escribe una respuesta de aprobacion o rechazo

## Archivos clave

- `tools/p12_to_flipper_bundle.py`
  Convierte un `.p12/.pfx` en un bundle `.fvp12` instalable por `Cert Vault`.

- `tools/fvp12_core.py`
  Carga el bundle, lo descifra, extrae identidad, resuelve el certificado y firma datos.

- `tools/fvp12_pdf_sign.py`
  Firma PDFs con `pyHanko` y genera la firma visible en el lateral derecho.

- `tools/fvp12_approval.py`
  Define el formato de solicitudes y respuestas `.req/.resp` y sus rutas locales.

- `tools/fvp12_sign_service.py`
  Servicio HTTP local. Sirve la pagina web, crea solicitudes, hace bridge con el Flipper y finaliza la firma.

- `tools/fvp12_sign_service_ui.html`
  Pagina web local para cargar el PDF, rellenar motivo/ubicacion/contacto y lanzar la solicitud.

- `tools/repro_fvp12_pdf_approval.ps1`
  Script de reproduccion del flujo clasico desde PowerShell. Ahora soporta `-Usb`, `health` y `wait` para el bridge USB real.

- `tools/flipper_usb_storage.py`
  Cliente USB standalone para listar, enviar, recibir y borrar ficheros en el Flipper sin depender de `flipper-sdk`.

- `flipper-sdk/applications_user/cert_vault/main.c`
  Fuente de la app del Flipper. Solo hace falta si quieres recompilar `Cert Vault`; no es una dependencia runtime del PC que firma.

## Rutas reales en el Flipper

La app `Cert Vault` trabaja sobre estas rutas del almacenamiento del Flipper:

- `/ext/apps_data/cert_vault/installed`
- `/ext/apps_data/cert_vault/requests`
- `/ext/apps_data/cert_vault/responses`

## Como funciona el flujo web con aprobacion

1. El navegador carga un PDF y envia un `POST /web-request-sign-pdf` al servicio local.
2. El servicio guarda temporalmente el PDF en `approval_exchange/.../web_stage`.
3. El servicio genera una solicitud `.req` con el motivo, el nombre del PDF, el hash y la identidad del firmante.
4. Esa solicitud se envia al Flipper de una de estas formas:
   - por SD montada, usando una ruta local tipo `X:/apps_data/cert_vault`
  - por USB, usando `tools/flipper_usb_storage.py`
5. La app `Cert Vault` muestra la primera solicitud pendiente.
6. En el Flipper se aprueba o se rechaza la solicitud.
7. El Flipper deja una respuesta `.resp` en `responses`.
8. El servicio detecta esa respuesta, firma el PDF real y devuelve el resultado al navegador.
9. El navegador descarga el PDF firmado y muestra la vista previa.

## Modos de bridge con el Flipper

### 1. SD montada

El servicio trabaja contra una ruta local montada por Windows.

Ejemplo:

`C:/py314/python.exe .\tools\fvp12_sign_service.py '48529495R' --vault-pin '4026' --exchange-dir '.\approval_exchange_test' --flipper-root 'X:/' --port 8766`

### 2. USB directo

El servicio usa `tools/flipper_usb_storage.py` para mover las solicitudes y respuestas por el puerto serie del Flipper.

Ejemplo:

`C:/py314/python.exe .\tools\fvp12_sign_service.py '48529495R' --vault-pin '4026' --exchange-dir '.\approval_exchange_test' --flipper-usb --port 8766`

Si hay un solo Flipper conectado, el puerto se detecta automaticamente. Si hace falta, puede forzarse con `--flipper-port COM7`.

El argumento `bundle` puede ser una ruta local, el nombre exacto del fichero instalado o un selector corto como el DNI/NIF. El servicio buscara la mejor coincidencia en `installed`.

## Rutas HTTP del servicio

- `GET /`
  Pagina web local.

- `GET /health`
  Estado del servicio y del bridge con el Flipper.

- `GET /info`
  Resumen del bundle e identidad activa.

- `GET /certificate.pem`
  Exporta el certificado activo en PEM.

- `GET /approval-status/<id>`
  Estado de una solicitud pendiente.

- `POST /web-request-sign-pdf`
  Flujo web con aprobacion en Flipper.

- `POST /web-finalize-sign-pdf`
  Finaliza la firma despues de la aprobacion.

- `POST /web-sign-pdf`
  Firma directa sin aprobacion. Se mantiene como ruta auxiliar de prueba.

- `POST /request-sign-pdf`
  Flujo clasico basado en rutas locales del PDF.

- `POST /finalize-sign-pdf`
  Finalizacion del flujo clasico.

- `POST /sign`
  Firma arbitraria de bytes, sin PDF.

## Comprobaciones utiles

### Estado rapido del servicio desde PowerShell

`pwsh -File .\tools\repro_fvp12_pdf_approval.ps1 -Action health -Usb`

### Ver que el Flipper responde por USB

Desde `d:\prueb_con\flipper`:

`C:/py314/python.exe .\tools\flipper_usb_storage.py list /ext/apps_data/cert_vault`

### Ver solicitudes pendientes en el Flipper

`C:/py314/python.exe .\tools\flipper_usb_storage.py list /ext/apps_data/cert_vault/requests`

### Ver respuestas del Flipper

`C:/py314/python.exe .\tools\flipper_usb_storage.py list /ext/apps_data/cert_vault/responses`

## Script de reproduccion por PowerShell

### Verificar que el servicio esta en modo USB

`pwsh -File .\tools\repro_fvp12_pdf_approval.ps1 -Action health -Usb`

### Crear una solicitud real

`pwsh -File .\tools\repro_fvp12_pdf_approval.ps1 -Action request -Usb -InputPdf .\approval_test_unsigned.pdf -OutputPdf .\approval_test_signed_usb.pdf`

### Esperar a que el Flipper apruebe o rechace

`pwsh -File .\tools\repro_fvp12_pdf_approval.ps1 -Action wait -RequestId <ID> -TimeoutSeconds 300`

### Finalizar la firma

`pwsh -File .\tools\repro_fvp12_pdf_approval.ps1 -Action finalize -Usb -RequestId <ID>`

### Simulacion local

Las acciones `simulate-approve` y `simulate-reject` siguen siendo utiles para pruebas locales, pero no sustituyen la aprobacion real del Flipper cuando usas `-Usb`.

## Problemas tipicos

### `PermissionError(13, 'Acceso denegado.', None, 5)` en `COM7`

El puerto del Flipper en Windows es exclusivo. Si otra herramienta lo abre, `tools/flipper_usb_storage.py` y el servicio Python fallan.

Culpables tipicos:

- `qFlipper`
- `lab.flipper.net/cli` o cualquier pagina Web Serial
- un monitor serie abierto en VS Code
- otra terminal o script que este usando `COM7`

Antes de usar el modo USB:

1. cierra `qFlipper`
2. pulsa `Disconnect` en la CLI web si estaba abierta
3. cierra cualquier monitor serie adicional

### El servicio dice que el bridge USB no esta disponible

Comprueba primero si este comando funciona:

`C:/py314/python.exe .\tools\flipper_usb_storage.py list /ext/apps_data/cert_vault`

Si eso falla, el problema no esta en la logica de firma, sino en el acceso al puerto o al dispositivo.

### El Flipper no muestra solicitudes pendientes

Comprueba si la solicitud ha llegado realmente al directorio del dispositivo:

`C:/py314/python.exe .\tools\flipper_usb_storage.py list /ext/apps_data/cert_vault/requests`

Si la ruta esta vacia, el bridge no esta escribiendo en el Flipper real.

## Resultado esperado

Cuando todo va bien:

- la pagina muestra `Flipper USB listo para aprobar` o una ruta de SD valida
- el Flipper muestra una solicitud pendiente en `Cert Vault`
- al aprobar, el navegador recibe un PDF firmado
- el PDF resultante contiene una firma digital y un sello visible lateral

## Ficheros temporales y limpieza

El servicio limpia automaticamente:

- la solicitud local `.req`
- la respuesta local `.resp`
- la respuesta y la solicitud espejadas en el bridge activo
- los PDFs temporales de `web_stage`

El documento original no se modifica. El resultado se entrega como un PDF nuevo `.signed.pdf`.