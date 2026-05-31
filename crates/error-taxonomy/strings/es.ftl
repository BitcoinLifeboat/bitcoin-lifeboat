# Bitcoin Lifeboat error catalog (es)
# Generated from the stable ErrorCode catalog shape; edit values, not keys.

errors-E-INPUT-001 =
    .title = Entrada vacía
    .description = No se proporcionó ningún descriptor ni archivo.
    .action = Pega un descriptor o elige un archivo.

errors-E-INPUT-002 =
    .title = Entrada demasiado grande
    .description = El archivo supera el límite de 10 MB.
    .action = Reduce el archivo o contacta al soporte si debería ser más pequeño.

errors-E-INPUT-003 =
    .title = Formato de archivo no válido
    .description = El contenido del archivo no coincide con ningún formato conocido de exportación de wallet.
    .action = Confirma que el archivo sea un descriptor (.txt, .json) o una exportación de wallet admitida.

errors-E-PARSE-001 =
    .title = No se puede interpretar el descriptor
    .description = El texto proporcionado no es un descriptor BIP380 válido.
    .action = Confirma que copiaste el descriptor completo, incluido cualquier `wsh(`/`wpkh(` inicial. Si tienes dudas, consulta las instrucciones de exportación por wallet.

errors-E-PARSE-002 =
    .title = Falta la suma de comprobación del descriptor
    .description = Los descriptores BIP380 deberían incluir una suma `#xxxxxxxx`.
    .action = Agrega la suma de comprobación (Lifeboat puede calcularla) o vuelve a exportar desde tu wallet.

errors-E-PARSE-003 =
    .title = Suma de comprobación del descriptor no válida
    .description = La suma de comprobación del descriptor no coincide con su contenido. El descriptor puede haberse transcrito mal.
    .action = Vuelve a exportar el descriptor desde tu software de wallet.

errors-E-PARSE-004 =
    .title = El descriptor mezcla redes
    .description = El descriptor contiene claves de varias redes Bitcoin (por ejemplo, mainnet y testnet).
    .action = Casi siempre es un error. Vuelve a exportar el descriptor y verifica que contenga solo claves mainnet (o solo testnet, si es intencional).

errors-E-PARSE-005 =
    .title = El descriptor contiene claves privadas
    .description = El descriptor incluye una clave privada extendida (xprv/yprv/zprv/tprv/uprv/vprv) o una clave privada sin procesar. Lifeboat se niega a procesar descriptores con material secreto.
    .action = Vuelve a exportar el descriptor en formato de solo observación (xpub en lugar de xprv).

errors-E-PARSE-006 =
    .title = Función de descriptor no admitida
    .description = El descriptor usa una función que Lifeboat aún no admite en esta versión (por ejemplo, raw(), addr()).
    .action = Usa una wallet que exporte un descriptor admitido (wpkh, wsh, sh(wpkh), multi, sortedmulti).

errors-E-PARSE-007 =
    .title = El umbral multisig supera el número de claves
    .description = El descriptor especifica M-de-N donde M > N, lo que nunca puede satisfacerse.
    .action = Confirma el descriptor; esto probablemente indica un error de transcripción.

errors-E-SECRET-001 =
    .title = Mnemónica BIP39 detectada
    .description = La entrada contiene una secuencia de palabras que coincide con una lista BIP39 y tiene una suma válida. Lifeboat no acepta frases semilla.
    .action = Exporta el DESCRIPTOR DE SALIDA (no la semilla) desde tu software de wallet y pégalo en su lugar.

errors-E-SECRET-002 =
    .title = Posible mnemónica BIP39 detectada
    .description = La entrada contiene una secuencia de palabras BIP39; la suma no validó, pero el patrón es sospechoso.
    .action = Si querías pegar un descriptor y esto es un falso positivo, escribe "I confirm this is not a real seed" para continuar.

errors-E-SECRET-003 =
    .title = Clave privada (WIF) detectada
    .description = La entrada coincide con el formato de clave privada WIF. Lifeboat no acepta claves privadas.
    .action = Usa la clave pública correspondiente o un xpub.

errors-E-SECRET-004 =
    .title = Clave privada extendida detectada
    .description = La entrada contiene un xprv / yprv / zprv / tprv / uprv / vprv. Lifeboat no acepta claves privadas extendidas.
    .action = Usa el xpub / ypub / zpub / tpub / upub / vpub correspondiente.

errors-E-SECRET-005 =
    .title = Compartición SLIP-39 detectada
    .description = La entrada parece ser una compartición Shamir SLIP-39.
    .action = Lifeboat no necesita comparticiones SLIP-39. Usa el descriptor de salida de tu wallet.

errors-E-SECRET-006 =
    .title = Secreto codex32 detectado
    .description = La entrada parece ser un secreto codex32 (BIP-93).
    .action = Lifeboat no necesita secretos codex32. Usa el descriptor de salida de tu wallet.

errors-E-SECRET-007 =
    .title = Posible clave privada sin procesar detectada
    .description = La entrada contiene una cadena hexadecimal de 64 caracteres en un contexto sospechoso (por ejemplo, junto a la palabra "private" o "key").
    .action = Confirma que esto no es una clave privada. Si querías usar un ID de transacción o hash de bloque, no debería aparecer en este campo.

errors-E-FS-001 =
    .title = Archivo no encontrado
    .description = La ruta de archivo proporcionada no existe o no se puede leer.
    .action = Verifica la ruta y los permisos, luego inténtalo de nuevo.

errors-E-FS-002 =
    .title = No se puede escribir en el destino
    .description = La ruta de destino no permite escritura.
    .action = Elige otro destino o revisa los permisos.

errors-E-FS-003 =
    .title = El archivo de destino ya existe
    .description = Ya existe un archivo en el destino.
    .action = Confirma la sobrescritura o elige otro nombre.

errors-E-NETWORK-001 =
    .title = Red no accesible
    .description = La llamada de red iniciada por el usuario falló.
    .action = Verifica tu conexión a internet o inténtalo más tarde.

errors-E-NETWORK-002 =
    .title = Intento de llamada de red inesperada
    .description = Interno: un componente intentó una llamada de red sin acción explícita del usuario.
    .action = Esto es un error. Abre un issue en el repositorio de GitHub.

errors-E-DEP-001 =
    .title = Typst no incluido
    .description = La generación de PDF requiere el binario Typst incluido, pero no se encontró.
    .action = Reinstala Lifeboat. Si el problema continúa, abre un issue.

errors-E-DEP-002 =
    .title = HWI no disponible
    .description = Las operaciones con hardware wallet requieren el binario sidecar HWI (v0.4+), pero no se encontró.
    .action = Reinstala la versión de Lifeboat que incluye HWI, o usa PSBT basada en archivos.

errors-E-LINK-001 =
    .title = Enlace externo no permitido
    .description = El enlace no está en la lista de URLs externas permitidas del proyecto.
    .action = Verifica el enlace manualmente en tu navegador si confías en él.

errors-E-INTERNAL-001 =
    .title = Error inesperado
    .description = Ocurrió un error interno inesperado.
    .action = Abre un issue en el repositorio de GitHub con los pasos para reproducirlo.

errors-E-INTERNAL-002 =
    .title = Se requiere migración de esquema
    .description = El archivo de configuración usa un formato de una versión anterior de Lifeboat.
    .action = Lifeboat intentará migrarlo. Si falla, elimina el archivo de configuración.

