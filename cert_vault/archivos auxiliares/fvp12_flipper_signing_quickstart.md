# FVP12 Flipper Signing Quickstart

## Que hace este flujo

1. Cargas un PDF en la pagina local.
2. El servicio crea una solicitud de firma.
3. La solicitud llega al Flipper por USB o por SD montada.
4. Apruebas o rechazas en `Cert Vault`.
5. Si apruebas, el navegador descarga el PDF firmado.

## Archivos importantes

- `tools/fvp12_sign_service.py`
- `tools/fvp12_sign_service_ui.html`
- `tools/fvp12_pdf_sign.py`
- `tools/fvp12_core.py`
- `tools/flipper_usb_storage.py`
- `tools/repro_fvp12_pdf_approval.ps1`

## Antes de empezar

1. El bundle `.fvp12` debe estar instalado en `Cert Vault`.
2. Si vas por USB, instala `pyserial` en el Python que usas para el servicio con `C:/py314/python.exe -m pip install pyserial`.
3. Si vas por USB, cierra `qFlipper`.
4. Si has usado `lab.flipper.net/cli`, pulsa `Disconnect` antes de arrancar el servicio.
5. No dejes otro monitor serie abierto sobre el `COM` del Flipper.
6. No necesitas copiar el `.fvp12` al PC para firmar; el servicio puede leerlo directamente desde `installed` en el Flipper.
7. No necesitas `flipper-sdk` en el PC para firmar; solo hace falta si quieres recompilar la app del Flipper.

## Comprobar que el Flipper responde por USB

Desde `d:\prueb_con\flipper`:

```powershell
C:/py314/python.exe .\tools\flipper_usb_storage.py list /ext/apps_data/cert_vault
```

Si responde, el bridge USB esta listo.

## Arrancar el servicio en modo USB

Desde `d:\prueb_con\flipper`:

```powershell
C:/py314/python.exe .\tools\fvp12_sign_service.py 'DNI' --vault-pin 'XXX' --exchange-dir '.\approval_exchange_test' --flipper-usb --port 8766
```

Puedes pasar el numero, el alias o el nombre del bundle. El servicio buscara la coincidencia en `/ext/apps_data/cert_vault/installed`.

Si el bundle instalado es de tipo legacy `pkcs12`, el servicio tambien pedira la contraseña original del PKCS#12.

## Abrir la pagina

Usa:

- `http://127.0.0.1:8766/`

Cuando todo esta bien, la pagina debe mostrar algo como:

- `Flipper USB listo para aprobar`
- `Flipper USB: USB serial storage via COM7`

## Flujo web normal

1. Carga el PDF.
2. Rellena nombre, DNI/NIF, motivo, ubicacion y contacto si quieres.
3. Pulsa `Enviar al Flipper y esperar aprobacion`.
4. En el Flipper entra en `Cert Vault`.
5. Revisa la solicitud pendiente.
6. Apruebala.
7. El navegador recibira el PDF firmado y mostrara el enlace de descarga.

## Flujo por PowerShell

### Ver estado del servicio

```powershell
pwsh -File .\tools\repro_fvp12_pdf_approval.ps1 -Action health -Usb
```

### Crear una solicitud real

```powershell
pwsh -File .\tools\repro_fvp12_pdf_approval.ps1 -Action request -Usb -InputPdf .\approval_test_unsigned.pdf -OutputPdf .\approval_test_signed_usb.pdf
```

### Esperar aprobacion o rechazo

```powershell
pwsh -File .\tools\repro_fvp12_pdf_approval.ps1 -Action wait -RequestId <ID> -TimeoutSeconds 300
```

### Finalizar la firma

```powershell
pwsh -File .\tools\repro_fvp12_pdf_approval.ps1 -Action finalize -Usb -RequestId <ID>
```

## Rutas del Flipper usadas por este flujo

- `/ext/apps_data/cert_vault/installed`
- `/ext/apps_data/cert_vault/requests`
- `/ext/apps_data/cert_vault/responses`

## Problema mas comun

### `PermissionError(13, 'Acceso denegado.', None, 5)`

Significa que el puerto `COMx` del Flipper ya esta abierto por otra herramienta.

Casi siempre es una de estas:

- `qFlipper`
- `lab.flipper.net/cli`
- un monitor serie en VS Code
- otra terminal o script que haya abierto el mismo puerto

Solucion:

1. cierra la herramienta que usa el puerto
2. pulsa `Disconnect` en la CLI web si estaba abierta
3. vuelve a probar `tools/flipper_usb_storage.py list /ext/apps_data/cert_vault`

## Resultado esperado

Cuando funciona bien:

- el Flipper muestra la solicitud pendiente
- la pagina pasa a `PDF firmado correctamente tras la aprobacion del Flipper`
- el PDF final se descarga como `.signed.pdf`
- la firma visible aparece en el lateral derecho del documento
