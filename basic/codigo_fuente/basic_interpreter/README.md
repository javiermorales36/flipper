# Flipper BASIC Interpreter

App de ejemplo para Flipper Zero que carga un archivo BASIC desde la tarjeta SD y lo ejecuta.

## Cómo usar

1. Copia `basic_interpreter` a tu firmware de Flipper:
   ```bash
   cp -r d:/prueb_con/flipper/basic_interpreter d:/prueb_con/flipper/flipper-sdk/applications_user/basic_interpreter
   ```
2. Coloca tu programa BASIC en la tarjeta SD con esta ruta:
   ```text
   /ext/basic/program.bas
   ```
3. El archivo puede usar comandos sencillos como:
   - `PRINT "texto"`
   - `LET A = 5`
   - `GOTO 100`
   - `IF A < 5 THEN 200`
   - `END`
4. Enciende la app en Flipper y presiona `OK` para ejecutarla.

## Ejemplo de programa

```basic
10 PRINT "HOLA MUNDO"
20 LET A = 1
30 IF A < 5 THEN 50
40 GOTO 60
50 PRINT "A ES MENOR QUE 5"
60 END
```

## Compilar y generar `.fap`

Desde tu firmware de Flipper Zero:

```bash
cd d:/prueb_con/flipper/flipper-sdk
./fbt TARGET_HW=DEV fap_dist
```

Después de la compilación, el paquete `.fap` estará en el directorio de salida de la herramienta.
