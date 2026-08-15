# Fiserv IPG — Documentación consolidada de integración (Argentina)

> **Documento único de referencia para homologación.** Consolida, de forma literal, los 8 documentos entregados por Fiserv. Está ordenado según el flujo real de implementación, no según el orden de los archivos originales. La numeración de secciones (§1, §10.1.4, Apéndice V, etc.) es la de la *Guía de Integración API Rest* original, para poder cruzar referencias con Fiserv.

**Armado:** 30 de julio de 2026 · **Alcance:** PXSOL SAS · Argentina (con notas de Uruguay donde el original las incluye)

## Documentos fuente

| # | Archivo original | Dónde quedó en este documento |
|---|---|---|
| 1 | `Guía de Integración API Rest Argentina 2026.pdf` (v2.0, jun-2025, ARG & URY) | Repartida por flujo: Partes 1, 2, 4, 5, 6, 7, 9, 10 |
| 2 | `Zero Auth 2.pdf` | Parte 3 |
| 3 | `Manual NetworkToken MTRG.pdf` | Parte 4 |
| 4 | `Comunicacion comercios 3DS.pdf` | Parte 5 |
| 5 | `Códigos-rechazo-declined-failed.pdf` | Parte 8 |
| 6 | `Penalizacion por Reintentos Visa - Master.pdf` | Parte 8 |
| 7 | `Credit cards for test.pdf` | Parte 10 |
| 8 | `Homologación - 3ds FULL API token PXSOL.docx` | Parte 11 |

## Cómo leer este documento

- **Contenido literal.** El texto, los payloads y las tablas se transcribieron sin resumir. Cuando el PDF original traía una errata (un JSON sin coma, un campo mal escrito), se preservó tal cual y se señaló, porque es lo que el gateway espera o rechaza en la práctica.
- **`> [Imagen en el documento original]`** marca un lugar donde el PDF tenía una captura o diagrama que no sobrevive a la extracción de texto. Si necesitás ese detalle visual, hay que ir al PDF.
- **`// [contenido truncado en el PDF original]`** marca un payload que ya venía cortado en el PDF fuente.
- Cada sección lleva una línea *Fuente:* con el archivo y la sección de origen.
- **Andamiaje editorial.** Tres cosas de este documento no vienen de los PDFs: los títulos "Parte N" y sus bajadas, las líneas *Fuente:*, y los captions del tipo "Bloque original tal como aparece en el PDF" que preceden a una transcripción cruda del layout. Además, unas pocas tablas del original no traían encabezado de columna y se les agregó uno (`Campo` / `Descripción`) para que rendericen. Ningún dato técnico fue agregado ni interpretado.

## Requisitos obligatorios por marca

Resumen de lo que cada marca exige, armado cruzando los ocho documentos. Cada fila remite a la sección donde está el detalle.

| | **Visa** | **Mastercard** |
|---|---|---|
| **3D Secure** | **Opcional.** Sin cargo. | **Obligatorio.** Hay que elegir entre *Data Only* o *EMV 3DS Full Authentication*. |
| **Costo 3DS** | Sin cargo (servicio opcional). | Data Only: sin cargo. Full: 0,025% de la transacción, tope USD 3 + IVA ("Cargo 3DS MC"). No autenticar: **SEF** de 0,025% por transacción no autenticada, tope USD 3. |
| **Network Token** | **Obligatorio.** *"Todas las transacciones realizadas con tarjetas Visa deben utilizar Network Token"*. | Compatible, no obligatorio. |
| **Recurrencia — FIRST** | Guardar el `SchemeTransactionId` que llega en la respuesta. Con Network Tokenization, enviar el criptograma. | Agregar los parámetros de 3DS **Data Only**. Con Network Tokenization, enviar el criptograma. |
| **Recurrencia — REPEAT** | Enviar el valor guardado en `ReferencedSchemeTransactionId`. Con NT, **no** hace falta el criptograma. | Enviar **sin 3DS**. Con NT, **no** hace falta el criptograma. |
| **MIT** | No disponible por ahora. | Disponible. |
| **Network Token passthrough** | `order.tokenCryptogram`. | `order.tokenCryptogram` **más** el bloque `storedCredentials` (`sequence`, `scheduled`, `initiator`, `indicatorSubcategory`). |
| **Reintentos** | 4 categorías según código ISO. Exceder: USD 0,10 local / USD 0,25 internacional. | Merchant Advice Code (MAC) por transacción. Exceder: USD 0,50, acumulable con la penalidad general de USD 0,50. Sin MAC en la respuesta: 7/día, máx. 35 en 30 días. |
| **Dónde leer el rechazo** | REST `associationResponseCode` / SOAP `ProcessorAssociationResponseCode`. | Igual, más `MerchantAdviceCodeIndicator` (descripción en `declineReasonCode` REST / `TransactionDeclineReason` SOAP). |

### 3DS Data Only — campos exactos

Data Only existe **solo para Mastercard**. Los campos cambian según quién autentica:

| Escenario | Bloque | Campos |
|---|---|---|
| Proveedor propio (§10.1.6) | `authenticationRequest` | `authenticationType: "Secure3DAuthenticationRequest"`, `termURL`, `methodNotificationURL`, `messageCategory: "80"` |
| Proveedor externo / passthrough (§10.2.2) | `authenticationResult` | `authenticationType: "Secure3DAuthenticationResult"`, `authenticationResponse: "U"`, `cavv`, `dsTransactionId`, `transactionStatus: "Y"`, `messageCategory: "80"` |
| Zero Auth sobre Mastercard | `authenticationRequest` | `authenticationType: "Secure3DAuthenticationRequest"`, `messageCategory: "80"`, `methodNotificationURL`, `termURL`. En SOAP: `<v1:CreditCard3DSecure>` con `AuthenticateTransaction=true` y `ThreeDSEmvCoMessageCategory=80` |

En la respuesta, Data Only devuelve `secure3dResponse.responseCode3dSecure` = **`A`** (Data Only exitosa) o **`B`** (no exitosa). Ambos mapean a **ECI7** y **no** dan liability shift: ante un desconocimiento, el contracargo lo asume el comercio. La transacción igualmente pasa a autorización.

### Network Token (MTRG) — lo que no se puede pasar por alto

- **Dos flujos.** *OnTheGo*: se manda el PAN y Fiserv consigue el token al instante. *Asíncrono*: se crea un `HostedDataID` y el token se provisiona en hasta 20 segundos.
- **Emparejamiento obligatorio.** En cada transacción aprobada hay que guardar BIN + últimos 4 del PAN **y** BIN + últimos 4 del Network Token. Sin eso no se pueden conciliar ni atender desconocimientos, porque lo que se procesa (y lo que vuelve) es el token, no el PAN.
- **En SOAP el orden de los parámetros importa**: mandarlos en otro orden genera errores.
- En passthrough, el token viaja en `CardNumber` (16 dígitos, como un PAN), con su propio `ExpMonth`/`ExpYear`, y el criptograma en base64. `CardCodeValue` no se requiere.

> **Este archivo contiene credenciales de sandbox.** La Parte 1 incluye las API Key / API Secret de certificación de PXSOL para Argentina y Uruguay. Son de prueba, pero conviene tratar el archivo como interno.

## Índice

0. [Requisitos obligatorios por marca](#requisitos-obligatorios-por-marca)
1. [Parte 1 — Fundamentos, credenciales y entorno](#parte-1--fundamentos-credenciales-y-entorno)
   - [0. Metadatos del documento original](#0-metadatos-del-documento-original)
   - [1. Introducción](#1-introducción)
   - [2. Flujo de integración](#2-flujo-de-integración)
   - [3. Primeros Pasos](#3-primeros-pasos)
   - [Credenciales de prueba (Sandbox / CERT) — PXSOL](#credenciales-de-prueba-sandbox--cert--pxsol)
   - [4. Estructura de las solicitudes HTTP](#4-estructura-de-las-solicitudes-http)
   - [Apéndice II. Generación de Message-signature](#apéndice-ii-generación-de-message-signature)
   - [Apéndice I. Estructura de objetos JSON.](#apéndice-i-estructura-de-objetos-json)
   - [5. Configuración del entorno de pruebas](#5-configuración-del-entorno-de-pruebas)
   - [6. Definición de los endpoints](#6-definición-de-los-endpoints)
2. [Parte 2 — Transacciones básicas](#parte-2--transacciones-básicas)
   - [7. Transacciones básicas](#7-transacciones-básicas)
   - [Apéndice III. Parámetros (mandatorios y opcionales) de una transacción de tipo PaymentCardSaleTransaction](#apéndice-iii-parámetros-mandatorios-y-opcionales-de-una-transacción-de-tipo-paymentcardsaletransaction)
   - [Apéndice VI. Transacciones comunes](#apéndice-vi-transacciones-comunes)
   - [8. Link de Pago (Payment URL)](#8-link-de-pago-payment-url)
3. [Parte 3 — Zero Auth](#parte-3--zero-auth)
   - [Zero Auth](#zero-auth)
4. [Parte 4 — Tokenización](#parte-4--tokenización)
   - [9. Tokenización](#9-tokenización)
   - [Network Token (MTRG)](#network-token-mtrg)
5. [Parte 5 — 3D Secure](#parte-5--3d-secure)
   - [10. 3D Secure](#10-3d-secure)
   - [Comunicación a comercios — 3D Secure](#comunicación-a-comercios--3d-secure)
6. [Parte 6 — Pagos recurrentes y Card on File](#parte-6--pagos-recurrentes-y-card-on-file)
   - [11. Pagos recurrentes](#11-pagos-recurrentes)
7. [Parte 7 — Payment Facilitator, Tax Refund y Wallet](#parte-7--payment-facilitator-tax-refund-y-wallet)
   - [12. Payment Facilitator](#12-payment-facilitator)
   - [Apéndice VII. Payment Facilitator (parámetros mandatories y opcionales)](#apéndice-vii-payment-facilitator-parámetros-mandatories-y-opcionales)
   - [13. Tax Refund Uruguay](#13-tax-refund-uruguay)
   - [15. Wallet](#15-wallet)
8. [Parte 8 — Manejo de errores, rechazos y reintentos](#parte-8--manejo-de-errores-rechazos-y-reintentos)
   - [Códigos de rechazo (declined / failed)](#códigos-de-rechazo-declined--failed)
   - [Penalización por reintentos (Visa / Mastercard)](#penalización-por-reintentos-visa--mastercard)
   - [Tabla de reintentos VISA (adjunto recuperado)](#tabla-de-reintentos-visa-adjunto-recuperado)
   - [Tabla de reintentos MASTERCARD (adjunto recuperado)](#tabla-de-reintentos-mastercard-adjunto-recuperado)
9. [Parte 9 — Buenas prácticas y seguridad](#parte-9--buenas-prácticas-y-seguridad)
   - [14. Buenas prácticas y anotaciones técnicas](#14-buenas-prácticas-y-anotaciones-técnicas)
10. [Parte 10 — Tarjetas y datos de prueba](#parte-10--tarjetas-y-datos-de-prueba)
   - [Apéndice IV. Tarjetas de Test para integraciones estándar](#apéndice-iv-tarjetas-de-test-para-integraciones-estándar)
   - [Apéndice V. Tarjetas de test para 3DS](#apéndice-v-tarjetas-de-test-para-3ds)
   - [Tarjetas de prueba (Credit cards for test)](#tarjetas-de-prueba-credit-cards-for-test)
11. [Parte 11 — Homologación](#parte-11--homologación)
   - [Checklist de homologación — 3DS FULL / API / Token (PXSOL)](#checklist-de-homologación--3ds-full--api--token-pxsol)
     - [Stores a usar y dónde está documentado cada caso](#stores-a-usar-y-dónde-está-documentado-cada-caso)
     - [⚠ Las tarjetas del checklist no coinciden con el Apéndice V](#-las-tarjetas-del-checklist-no-coinciden-con-el-apéndice-v-de-la-guía)
     - [Verificado en vivo contra CERT (2026-08-06)](#verificado-en-vivo-contra-cert-2026-08-06)
     - [Preguntas abiertas para Fiserv](#preguntas-abiertas-para-fiserv)

---

# Parte 1 — Fundamentos, credenciales y entorno

Qué es la API, cómo se autentica cada request y cómo dejar el sandbox andando antes de escribir la primera transacción.

## 0. Metadatos del documento original

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — portada*

Manual de integración — IPG API Rest

2025

Versión 2.0

Fecha: junio 2025

ARG & URY

Confidencial y de propiedad exclusiva de Fiserv

El presente documento está dirigido a los desarrolladores que desean integrarse con la solución IPG de Fiserv para procesar pagos en sistemas de e-commerce y utilizando la opción Rest API. Para su total comprensión e interpretación se requieren conocimientos intermedios – avanzados sobre el consumo de servicios web Restful. Así mismo, es importante que el desarrollador conozca por completo el lenguaje de programación que utilizará para implementar su solución.

El objetivo principal de este documento es guiar al desarrollador para la configuración de un entorno de pruebas (Sandbox) donde pueda probar las operaciones que ofrece IPG en su opción Rest API.

## 1. Introducción

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §1*

IPG es la solución de Fiserv que te permite procesar transacciones desde un sitio web a través de un canal seguro y se adapta a las necesidades del comercio para realizar operaciones bancarias como pagos, devoluciones, cancelaciones, pre-autorizaciones y post-autorizaciones; así como consultar el estatus de las transacciones, generación de Payment URL y completa personalización de la experiencia al comprador.

IPG Rest API ofrece un conjunto de herramientas que permiten realizar pagos a través de la definición de un Servicio Web. A diferencia de la solución Connect, la opción Rest API permite a los desarrolladores definir por su cuenta el flujo de operación y cobro de las transacciones, así como completa personalización de los formularios para capturar la información de los tarjetahabientes. Adicionalmente, se puede integrar a cualquier tipo de aplicación web gracias a que la comunicación consiste en el intercambio de mensajes (solicitudes HTTP) desde la aplicación al servidor de IPG.

La integración por Rest API está orientada a un desarrollo más robusto que requiera funcionalidades superiores a la opción Connect, requiere un equipo de desarrollo más especializado, pero permite que el aplicativo desarrollado sea escalable y tener control completo del flujo transaccional.

## 2. Flujo de integración

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §2*

El proceso de comunicación entre el Gateway de IPG y tu aplicación se realiza a través de la construcción de peticiones HTTP. Estas peticiones son enviadas y procesadas por el servidor de IPG, posteriormente se genera una respuesta que tu aplicación debe capturar e interpretar para mostrar el resultado o continuar procesando.

La respuesta puede ser recibida en tu propio servidor a través de una URL que permita el método POST.

Una vez obtenida la respuesta, es responsabilidad de la lógica del negocio y del comercio definir qué desea realizar con ella; algunos ejemplos van desde almacenar en su propia base de datos, enviar correos electrónicos/mensajes de texto de confirmación, o simplemente mostrar un cuadro de dialogo con el resultado de la operación.

## 3. Primeros Pasos

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §3*

Para comenzar la integración con la Rest API, asegúrate de contar con la siguiente información:

- **API Key.** Es una clave que identifica al comercio y proporciona permiso para procesar las transacciones dentro del servidor.
- **API Secret.** Es el equivalente a una contraseña PRIVADA y no debe ser compartida con nadie, se utiliza en conjunto con API Key para autenticarte cada que envías una solicitud HTTP.
- **Archivo postman_environment.json.** Es la definición de tu entorno personalizado para realizar pruebas.
- **Archivo postman_collection.json.** Es una colección de solicitudes HTTP preconstruidas que contienen transacciones de ejemplo para probar la API.

## Credenciales de prueba (Sandbox / CERT) — PXSOL

*Fuente: credenciales provistas por Fiserv al equipo de PXSOL. No forman parte de los PDFs originales.*

> **Solo entorno de certificación.** Estas credenciales apuntan a `cert.api.firstdata.com` y sirven únicamente para pruebas y homologación. Aun así son secretos: este archivo no debería subirse a un repositorio público ni compartirse fuera del equipo. Las credenciales de producción son distintas y las entrega Fiserv al aprobar la homologación.

**Endpoint (mismo para los dos países):**

```http
https://cert.api.firstdata.com/gateway/v2
```

### Argentina

| | Valor |
|---|---|
| Store ID | `5926072901` |
| Store ID | `5926072902` |
| API Key | `4w7jLvtvJBoMWK9Jq5MfC0JUMaDLLr4Xs7YSGl660HWueGdz` |
| API Secret | `d7nW6rbZkUag5RgatwUqAeNJhMMdsqLUfavNLq1eUDgokZCKu5RCXctLLWy0Mtjr` |

Los dos stores no son intercambiables para la homologación: el checklist pide **`5926072902` para el caso de TOKEN GW** y **`5926072901` para el caso de TOKEN MTRG** (ver Parte 11).

### Uruguay

| | Valor |
|---|---|
| Store ID | `7726072903` |
| Store ID | `7726072904` |
| API Key | `w9viH4xlfULCEGU2upZ4sdRIGJf0RzXGw4u2wXtkih4owGuV` |
| API Secret | `3Kv5W8MnHgT6ut1keiOuU7aiqTA7GhOGRnrxbOqfF3BA3nyaBWA9cV81mMRXzVgA` |

El API Key y el API Secret se usan para firmar cada request: ver §4 (headers) y el Apéndice II (generación de `Message-signature`), donde el secret entra como clave del HMAC-SHA256 y el key como primer término de la cadena a firmar.

## 4. Estructura de las solicitudes HTTP

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §4*

Una solicitud HTTP es un mensaje que cuenta con una estructura y está compuesta por diversas partes descritas a continuación:

- **Endpoint:** es un recurso que vive en un servidor web, este recurso puede ser consultado desde una aplicación cliente que lo solicite y devuelve una respuesta. Su estructura es la de una URL, por ejemplo:

  ```http
  https://webserver.com/getOrders?param1=value1&param2=value2...&paramn=valuen
  ```

  El endpoint anterior corresponde al recurso getOrders que vive en el servidor que es accesible a través de la URL https://webserver.com.

  Es posible enviar parámetros adicionales que complementen la solicitud.

- **Método:** especifica la operación que realiza el endpoint que estamos consultado y puede tomar los siguientes valores:

  - GET: Obtener información.
  - POST: Enviar información.
  - DELETE: Borrar un recurso.
  - PATCH: Actualizar un recurso existente.

  Además de estos métodos existen algunos otros, sin embargo, no son utilizados por IPG Rest API.

- **Cuerpo/Payload:** Es el contenido o información que estamos enviando dentro de nuestra solicitud HTTP. Este elemento únicamente existe para las peticiones con método POST, PATCH. IPG Rest API permite únicamente objetos JSON dentro del cuerpo de la solicitud, para más información sobre su estructura consulta el Apéndice I.

- **Encabezados:** los encabezados especifican al servidor el tipo de mensaje que estamos enviando, el contenido, los parámetros de autenticación, tamaño del mensaje, etc. La finalidad de los encabezados es indicar al servidor cómo debe interpretar la solicitud. En el caso de IPG Rest API se requieren los siguientes encabezados para todas las peticiones que envíe tu aplicación.

| Encabezado | Valor |
| --- | --- |
| Content-Type | application/json |
| Api-Key | El valor de tu API Key |
| Client-Request-Id | Identificador único para cada solicitud. Se sugiere utilizar el estándar UUID de 128 bits. Ej. ED280816-E404-444AA2D9-FFD2D171F928 |
| Timestamp | Valor correspondiente al número de milisegundos transcurridos desde el 01/01/1970 hasta el instante en que se está realizando la petición. También se le conoce como Epoch time. Ej. 1582828266 |
| Message-Signature | Es un hash generado con los datos que estamos enviando. Se utiliza para que el servidor garantice la autenticidad de la solicitud HTTP. |

## Apéndice II. Generación de Message-signature

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §Apéndice II*

Para cada una de las solicitudes HTTP que enviemos es necesario generar un Hash (Message-Signature) que utiliza nuestro servidor para validar la autenticidad e integridad del mensaje. Este hash es enviado en el header dentro de la petición HTTP como Message-Signature. Detalles:

- Algoritmo: HMAC SHA256
- Encoding: Base64
- Firmado con: "API SECRET" provista al comercio por parte de fiserv

Paso 1 - Generar una cadena de texto con la siguiente estructura msgSignatureString = API_KEY + CLIENT_REQUEST_ID + TIMESTAMP + PAYLOAD.

En donde:

- API_KEY: Es la clave de acceso a la API provista por fiserv. Ejemplo: tOqWgOZAFq6aAYpqyQtAGVkjfo2Qp3lUxd
- CLIENT_REQUEST_ID: Es un identificador único para cada transacción. Se recomienda utilizar el formato UUIDv4 universally unique identifier (UUID) de 128 bits hay diferentes librerías dependiendo el lenguaje de programación que utilicemos que nos podrían ayudar con esta tarea.
- TIMESTAMP: Valor correspondiente al número de milisegundos transcurridos desde el 01/01/1970 hasta el instante en que se está realizando la petición. También se le conoce como Epoch time. Ejemplo: 1650590066714
- PAYLOAD: Cuerpo/Body de la solicitud, el cual irá cambiando según el tipo de solicitud. En caso de que el Payload sea nulo, se debe considerar como una cadena vacía. El payload deberá ser serializado sin espacios en blanco ni saltos de línea como se muestra a continuación.

| Payload Original | Payload enviado |
| --- | --- |
| `{`<br>`  “name”:”Fiserv”,`<br>`  “location”: “Jaime Balmes 11D”`<br>`}` | `{“name”:”Fiserv”,“location”:“Jaime Balmes 11D”}` |

Bloque original de la tabla, tal como aparece en el documento:

```
 Payload Original                              Payload enviado
 {
   “name”:”Fiserv”,                            {“name”:”Fiserv”,“location”:“Jaime Balmes
   “location”: “Jaime Balmes 11D”              11D”}
 }
```

Paso 2 - Firmar la cadena resultante usando el algoritmo HMAC SHA256 y utilizando como llave tu API SECRET.

```javascript
strHash = HmacSHA256( msgSignatureString, API SECRET )
```

Paso 3 - Obtener la representación en base64 de la cadena resultante del paso anterior. El resultado de esto es lo que incluiremos como valor en el header Message-Signature de nuestra petición.

```javascript
b64Hash = strToBase64 (strHash)
```

## Apéndice I. Estructura de objetos JSON.

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §Apéndice I*

La estructura base de un objeto JSON es la siguiente:

```text
{
     “key1”:”value1”,
     “key2”:”value2”,
 .
 .
 .
     “keyN”:”valueN”
}
```

Todas las claves (key) son una cadena de texto que identifica al valor que mandamos como “value”. Los valores posibles que se pueden enviar son numéricos, cadenas de texto (solo estos se colocan entre comillas), booleanos, otros objetos JSON y arreglos de objetos JSON.

Ejemplo.

```json
{
     "merchantName":"fiserv Mexico",
     "merchantAddress":{
            "street":"Jaime Balmes",
            "streetNumber":"11D",
            "country": "Mexico"
     },
       "contact":[
            {
                   "id":1,
                   "name":"main",
                   "type": "phone",
                   "value":"55 1102 0600"
              },
              {
                   "id":2,
                   "name":"main email",
                   "type":"email",
                   "value":"myemail@mail.com"
              }
     ]
}
```

## 5. Configuración del entorno de pruebas

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §5*

Con la finalidad de que realices todas las pruebas necesarias para poder ejecutar y probar las transacciones es necesario que cuentes con la herramienta Postman, esta herramienta te permite construir y enviar peticiones HTTP, así como recibir la respuesta desde el servidor que consultemos. A continuación, se describe el procedimiento de instalación y configuración de la herramienta.

1. Descarga Postman de forma gratuita, disponible en el siguiente enlace: https://www.postman.com/downloads/. Se sugiere utilizar la versión 7.18.0 o superior, ya que para el desarrollo de este documento se utilizó esa versión base.

2. Instala la herramienta en tu computadora.

3. La primera ocasión que ejecutamos la herramienta se presentará una pantalla de inicio de sesión. En caso de no contar con una cuenta registrada en Postman, selecciona la opción enmarcada en la siguiente imagen.

> **[Imagen en el documento original]** — Captura de la pantalla de inicio de sesión de Postman, con la opción para continuar sin cuenta registrada enmarcada.

4. Dentro de la pantalla principal de Postman tendrás que importar la colección y el entorno de pruebas correspondiente a las pruebas preconstruidas para verificar el funcionamiento correcto de la API (la collection será proporcionada por Fiserv). Para ello, presiona el botón “Importar/Import” ubicado en la parte superior izquierda.

> **[Imagen en el documento original]** — Captura de la pantalla principal de Postman señalando el botón “Importar/Import” en la parte superior izquierda.

5. En la ventana emergente selecciona el botón “Choose Files” y selecciona los archivos de la colección y entorno a cargar. El nombre de estos archivos termina con “.postman_collection.json” y “.postman_environment.json” respectivamente. Puedes seleccionar ambos archivos al mismo tiempo.

> **[Imagen en el documento original]** — Captura de la ventana emergente de importación de Postman con el botón “Choose Files”.

6. Para verificar que la colección y el entorno se hayan cargado correctamente revisa lo siguiente:

   a. La colección se encuentra en la pestaña “Colecciones/Collections” en el panel lateral izquierdo de la aplicación.

   > **[Imagen en el documento original]** — Captura del panel lateral izquierdo de Postman mostrando la colección cargada en la pestaña “Colecciones/Collections”.

   b. En la parte superior derecha de la aplicación encontrarás una lista desplegable en donde se encuentran los entornos cargados en la herramienta. Selecciona el entorno de pruebas correspondiente al entorno de pruebas de IPG. Tendrá una apariencia similar a la siguiente.

   > **[Imagen en el documento original]** — Captura de la lista desplegable de entornos de Postman con el entorno de pruebas de IPG seleccionado.

7. Modifica tus credenciales (ApiKey y ApiSecret) proporcionadas por fiserv.

   a. Presiona el engrane ubicado en la parte derecha donde se muestra el entorno seleccionado.

   b. Presiona en el nombre del entorno de pruebas, llena con tus credenciales las variables “api_key” y “api_secret” de la tabla que se muestra.

   > **[Imagen en el documento original]** — Captura de la ventana de edición del entorno de Postman con las variables “api_key” y “api_secret”.

   c. Presiona el botón “Actualizar/Update”.

   d. Cierra la ventana emergente.

8. Ejecuta la solicitud de prueba (request) con nombre “API TEST” seleccionándola y presionando el botón “Enviar/Send”. Es muy importante que utilices la colección proporcionada, ya que contiene scripts de código que permiten construir cada una de las peticiones automáticamente de acuerdo con la estructura definida en la documentación de la API. Deberás obtener una respuesta como la que se muestra a continuación.

> **[Imagen en el documento original]** — Captura de Postman mostrando la respuesta obtenida al ejecutar la solicitud “API TEST”.

9. Si el resultado es similar al anterior y el “Status Code” de la respuesta HTTP es igual a 200, puedes ejecutar cualquier solicitud HTTP de la colección.

## 6. Definición de los endpoints

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §6*

En el entorno de pruebas todas las peticiones deberán apuntar a la siguiente URL:

```http
https://cert.api.firstdata.com/gateway/v2
```

Cuando termines de realizar tus pruebas se te proporcionará acceso a un entorno productivo que deberá apuntar a una URL de producción.


---

# Parte 2 — Transacciones básicas

Sale, PreAuth, PostAuth, Void, Return, consulta de estado y link de pago.

## 7. Transacciones básicas

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §7*

### 7.1 Conceptos

**Transacciones: conceptos**

| Tipo de transacción (Payload) | Descripción |
| --- | --- |
| PaymentCardSaleTransaction | También conocida como “venta”, es el tipo de transacción más común. Mediante esta transacción, la venta impactará de inmediato en la tarjeta de un cliente. |
| PaymentCardPreAuthTransaction | También conocida como “preautorización”, es aquella transacción que únicamente reserva fondos en la tarjeta de crédito de un cliente. Es la primera parte de la llamada “compra en 2 pasos”. Algunas características importantes:<br>• Mediante una preautorización no se efectúa el pago con una tarjeta hasta que se realice una captura (postauth) y/o confirme el envío del pedido (usando una opción disponible en Reportes, en la Terminal Virtual).<br>• No es posible operar mediante preautorización y captura con tarjetas de débito (sólo crédito y prepagas).<br>• Este tipo de transacción está disponible actualmente solo para Visa y Mastercard.<br>• Tenga en cuenta que la preautorización reserva fondos por períodos variables, según la política de la compañía emisora de la tarjeta. Le recomendamos encarecidamente que complete la transacción mediante una postautorización lo antes posible. |
| PostAuthTransaction | También conocida como “postautorización” o “captura”. Esta transacción captura los fondos reservados mediante una preautorización, por el monto especificado. Es la segunda parte de la llamada “compra en 2 pasos”. Algunas características importantes:<br>• Si captura un monto mayor que el especificado en la preautorización, puede hacerlo solo hasta un monto 10% mayor que el tomado en la preautorización (pese a ello, la misma puede ser rechazada por el emisor).<br>• Si captura un monto menor, la plataforma no establece un límite, excepto que debe ser mayor a 1 peso.<br>• Este tipo de transacción está disponible actualmente solo para Visa y Mastercard.<br>• No es posible operar mediante preautorización y captura con tarjetas de débito (sólo crédito y prepagas). |
| VoidTransaction * | También conocida como “anulación”. Mediante una anulación la transacción original se cancela por el total de lo cobrado (el tarjetahabiente no verá reflejado el movimiento en su resumen). La anulación de tipo “VoidTransaction” solo puede efectuarse:<br>• Si desea anular un sale: únicamente durante el día en que se efectuó el sale, antes del cierre de lote (23:30 horas)<br>• No es posible realizar anulaciones de postautorizaciones. |
| VoidPreAuthTransactions * | También conocida como “anulación”. Mediante una anulación la transacción original se cancela por el total de lo cobrado (el tarjetahabiente no verá reflejado el movimiento en su resumen). La anulación de tipo “VoidPreAuthTransactions” solo puede efectuarse:<br>• Si desea anular una preauth: 21 días (pasado dicho plazo, si la misma no se capturó, se depura; si pasado este plazo se intenta capturar, queda a consideración del emisor).<br>• No es posible realizar anulaciones de postautorizaciones. |
| ReturnTransaction | También conocido como “devolución”. La devolución genera un movimiento de credito en la cuenta del cliente (el tarjetahabiente verá reflejado en su resumen el cobro y la devolución). La devolución solo puede efectuarse:<br>• Si desea devolver un sale: puede hacer una devolución inmediatamente después de efectuado el cobro, y hasta 180 días después.<br>• Si desea devolver una postauth: puede hacer una devolución inmediatamente después de efectuada la captura, y hasta 180 días después.<br>• No es posible realizar devoluciones de preautorizaciones. |

\* Importante:

- Para anular una preauth debe obligatoriamente utilizar el requestType VoidPreAuthTransactions.
- Para anular un sale o una postauth debe obligatoriamente utilizar el requestType VoidTransaction.

Si se utilizan estos requestType de otra forma, las transacciones no se anularán, cualquiera sea la respuesta de IPG.

### 7.2 Parámetros mandatorios y opcionales

**Transacciones Primarias**

| | |
| --- | --- |
| requestType<br>(siempre mandatorio) | PaymentCardSaleTransaction<br>PaymentCardPreAuthTransaction |
| Campos mandatorios | transactionAmount /total<br>transactionAmount/currency<br>paymentMethod/paymentCard/number<br>paymentMethod/paymentCard/expiryDate |
| Campos opcionales | paymentMethod/paymentCard/securityCode<br>paymentMethod/paymentCard/cardFunction<br>paymentMethod/paymentCard/cardholderName<br>merchantTransactionId<br>transactionOrigin<br>Order/orderId<br>Billing/name<br>Billing/customerId<br>Billing/birthdate<br>Contact/phone<br>Contact/mobilePhone<br>Contact/fax<br>Contact/email<br>Address/address1<br>Address/address2<br>Address/city<br>Address/region<br>Address/postalCode<br>Address/country<br>Shipping/name<br>Shipping/Contact/phone<br>Shipping/Contact/mobilepHone<br>Shipping/Contact/fax<br>Shipping/Contact/email<br>Shipping/Address/company<br>Shipping/Address/address1<br>Shipping/Address/address2<br>Shipping/Address/city<br>Shipping/Address/region<br>Order/Shipping/Address/postalCode<br>SoftDescriptor/dinamycMerchantName<br>additionalDetails/comments<br>additionalDetails/invoicenumber<br>additionalDetails/invoiceperiod<br>additionalDetails/purchaseOrderNumber<br>Order/installmentOptions/numberOfinstallments *<br>Order/installmentOptions/Interest * |

\* Para sale o preauth en cuotas debe añadirse:

- Mandatorio: Order/installmentOptions/numberOfinstallments
- Opcional: Order/installmentOptions/Interest

**Transacciones Secundarias: PostAuthTransaction**

| | |
| --- | --- |
| requestType<br>(siempre mandatorio) | PostAuthTransaction |
| Campos mandatorios * | PATH PARAMS/TransactionID<br>PATH PARAMS/OrderId |
| Campos que no aplican | paymentMethod/paymentCard/number<br>paymentMethod/paymentCard/expiryDate |

\* Para postauth debe enviarse solo uno de los dos: TransactionID u OrderID.

**Transacciones Secundarias: VoidTransaction / VoidPreAuthTransactions**

| | |
| --- | --- |
| requestType *<br>(siempre mandatorio) | VoidTransaction<br>VoidPreAuthTransactions |
| Campos mandatorios ** | PATH PARAMS/TransactionID<br>PATH PARAMS/OrderId |

\* Debe enviarse como requestType:

- Para void de una preauth: VoidPreAuthTransactions
- Para void de un sale o una postauth: VoidTransaction

\*\* Para void debe enviarse solo uno de los dos: TransactionID u OrderID.

**Transacciones Secundarias: ReturnTransaction**

| | |
| --- | --- |
| requestType<br>(siempre mandatorio) | ReturnTransaction |
| Campos mandatorios * | PATH PARAMS/TransactionID<br>PATH PARAMS/OrderId<br>transactionAmount /total<br>transactionAmount/currency |

\*\* Para return debe enviarse solo uno de los dos: TransactionID u OrderID, además del importe (total y currency).

Adicionalmente, puede encontrar ejemplos armados de payloads en el Apéndice VI, “Transacciones comunes”, y en la collection brindada por Fiserv. Asimismo, puede ver un detalle completo de una transacción de requestType PaymentCardSaleTransaction en el Apéndice III, “Parámetros (mandatorios y opcionales) de una transacción de tipo PaymentCardSaleTransaction”

### 7.3 Consulta del estado de la transacción

Endpoint utilizado para consultar el estatus de alguna transacción efectuada, ya sea primaria o secundaria. No requiere payload y se envía el identificador de la transacción u orden a consultar en la URL. Se recibe un Payload de tipo TransactionResponse u OrderResponse respectivamente a la respuesta.

\* En caso de consultar el estado de una transacción de un store que forma parte de un grupo de stores, asociados todos a un mismo nodo, la consulta debe realizarse así:

```http
{{base_url}}/payments/{{ipgTransactionId}}?storeId=5923092899
```

## Apéndice III. Parámetros (mandatorios y opcionales) de una transacción de tipo PaymentCardSaleTransaction

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §Apéndice III*

A continuación, encontrará en detalle la mensajería correspondiente a una transacción de tipo PaymentCardSaleTransaction, indicando si el campo es mandatorio u opcional:

- **Campos mandatorios:**
  - requestType: nombre de la solicitud de la transacción principal.
  - transactionAmount: monto de la transacción. Se compone de los parámetros:
    - i. total: importe de la transacción (en números)
      - a. currency: moneda de la transacción (ejemplo: ARS)
    - ii. storeId: número de store

- **Campos opcionales:**
  - i. merchantTransactionId: ID único de la transacción generado por el comercio, si se proporciona.
  - ii. ipgTransactionId: ID de la transacción generado por IPG que hace referencia a una transacción.
  - iii. paymentMethod: alguno de los varios métodos de pago que admite el Gateway
    - a. paymentCard:
      - a) number: número de la tarjeta
      - b) securityCode: código de seguridad de la tarjeta
      - c) expiryDate:
        - i. month: mes de vencimiento de la tarjeta
        - ii. year: año de vencimiento de la tarjeta
      - d) cardFunction: tipo de tarjeta. Los valores posibles son: CREDIT, DEBIT, PREPAID
      - e) cardholderName: nombre del titular de la tarjeta
    - b. paymentFacilitator: detalles respecto al payment facilitator provistos por el comercio
      - a) subMerchantData: una vez que se proporciona el elemento subMerchant, la transacción es considerada como una transacción de subMerchant.
        - i. mcc: MCC del submerchant
        - ii. legalName: Legal Name del submerchant
        - iii. email: email del submerchant
        - iv. timezone: timezone del país donde se va a realizar la transacción (ejemplo: America/Buenos_Aires)
        - v. address: Información del domicilio del submerchant
          1. company: nombre de la empresa del submerchant
          2. address1: primera línea de la dirección de la calle del domicilio del submerchant
          3. address2: segunda línea de la dirección de la calle del domicilio del submerchant
          4. city: ciudad del submerchant
          5. región: estado o provincia del submerchant
          6. postalCode: Código Postal o ZIP code del submerchant
          7. country: país (ejemplo: ARG)
        - vi. document: información sobre la identificación del submerchant
          1. type: tipo de documento de identificación del submerchant (ejemplo: SINGLE_TAX_IDENTIFICATION)
          2. number: número del documento de identificación del submerchant
        - vii. merchantId: ID del submerchant (generado por el payment facilitator), único por cada submerchant
  - iv. order: utilice esta sección para proporcionar detalles relacionados con el pedido.
    - a. orderId: ID del pedido, si lo proporciona el cliente. Si no lo proporciona el cliente, IPG lo generará.
    - b. billing: información de facturación del cliente
      - a) name: nombre de facturación
      - b) customerId: ID del cliente para fines de facturación
      - c) birthDate
      - d) contact: información de contacto del cliente
        - i. phone
        - ii. mobilePhone
        - iii. fax
        - iv. email
      - e) address: Información del domicilio que se envía al emisor
        - i. company: nombre de la empresa asociada a la dirección
        - ii. address1: primera línea de la dirección de la calle
        - iii. address2: segunda línea de la dirección de la calle
        - iv. city: ciudad
        - v. región: estado o provincia
        - vi. postalCode: Código Postal o ZIP code
        - vii. country: país (ejemplo: ARG)
    - c. shipping: información de envío
      - a) name: nombre de facturación
      - b) contact: información de contacto del cliente
        - i. phone
        - ii. mobilePhone
        - iii. fax
        - iv. email
      - c) address: Información del domicilio que se envía al emisor
        - i. company: nombre de la empresa asociada a la dirección
        - ii. address1: primera línea de la dirección de la calle
        - iii. address2: segunda línea de la dirección de la calle
        - iv. city: ciudad
        - v. region: estado o provincia
        - vi. postalCode: Código Postal o ZIP code
        - vii. country: país (ejemplo: ARG)
    - d. serviceLocation: Detalles de la ubicación del servicio del comercio
      - a) city
      - b) state
      - c) zip
      - d) country
    - e. ip: dirección de red IPv4 o IPv6.
    - f. installmentOptions: indica si el importe de la transacción se dividirá en cuotas
      - a) numberOfInstallments: número de cuotas
      - b) recurringType: indica el tipo de pago recurrente (FIRST o REPEAT)
      - c) merchantAdviceCodeSupported: indica si el comerciante admite el código de aviso del comerciante (MAC) para recibir el código de la tabla 55 para una transacción recurrente rechazada (TRUE o FALSE)
    - g. tokenCryptogram: valor del criptograma del token de red (Network Tokenization)
    - h. softDescriptor: nombre del comercio que aparecerá en los estados de cuenta de la tarjeta de crédito/débito del comprador.
      - a) dynamicMerchantName: nombre de la tienda
      - b) customerServiceNumber: Información del número de teléfono de servicio al cliente que se pasa al emisor (puede aparecer en el estado de cuenta del titular de la tarjeta)
      - c) mcc: código de categoría de comerciante (MCC) de 4 dígitos
    - i. additionalDetails: Números de seguimiento proporcionados por el comerciante
      - a) merchantParameters
      - b) comments: comentarios sobre el pago
      - c) invoiceNumber: número de la factura
      - d) invoicePeriod: período de facturación en formato mes/año (MM/AA).
      - e) purchaseOrderNumber: número de orden de compra
        - i.

- Puede encontrar más información en https://docs.apis-fiserv.com/latam/docs/test

## Apéndice VI. Transacciones comunes

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §Apéndice VI*

A continuación, algunas transacciones más comunes:

**Sale:**

```json
{
    "transactionAmount": {
       "total": "20.00",
       "currency": "ARS"
    },
    "requestType": "PaymentCardSaleTransaction",
    "storeId": "5912345678",
    "paymentMethod": {
       "paymentCard": {
          "number": "5165850000000008",
          "securityCode": "123",
          "expiryDate": {
             "month": "12",
             "year": "29"
          }
       }
    },
// [contenido truncado en el PDF original]
// la llave de cierre siguiente NO está en el PDF: se agregó solo para cerrar el bloque
}
```

Esta transacción consta de los siguientes objetos:

| Objeto | Descripción |
| --- | --- |
| requestType | [string] indica el tipo de transacción a realizar "PaymentCardSaleTransasction" |
| transactionAmount | Indica el total a cobrar y el tipo de moneda<br>• total:[number] total a transaccionar mínimo: 0 ejemplo: 122.04<br>• currency: [string] ISO 4217 currency code. ejemplo: "ARS" |
| paymentMethod | Indica la información del método de pago<br>• paymentCard<br>&nbsp;&nbsp;&nbsp;&nbsp;• number:[number] 16 dígitos de la tarjeta<br>&nbsp;&nbsp;&nbsp;&nbsp;• securityCode:[number] 3 dígitos CVV<br>&nbsp;&nbsp;&nbsp;&nbsp;• expiryDate<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;• month:[number] mes de expiración de la tarjeta<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;• year: año de expiración de la tarjeta |

Bloque original de la tabla, tal como aparece en el documento:

```
                                     [string] indica el tipo de transacción a realizar
    requestType
                                             "PaymentCardSaleTransasction"
                  Indica el total a cobrar y el tipo de moneda
transactionAmount     • total:[number] total a transaccionar mínimo: 0 ejemplo: 122.04
                      • currency: [string] ISO 4217 currency code. ejemplo: "ARS"
                  Indica la información del método de pago
                      • paymentCard
                                • number:[number] 16 dígitos de la tarjeta
  paymentMethod                 • securityCode:[number] 3 dígitos CVV
                                • expiryDate
                                        • month:[number] mes de expiración de la tarjeta
                                        • year: año de expiración de la tarjeta
```

Si adicionalmente se quiere hacer la transacción en 6 cuotas, debe agregarse:

```json
    "order": {
       "installmentOptions": {
          "numberOfInstallments": 6
       }
    }
```

**Pre auth:**

```json
{
    "transactionAmount": {
       "total": "5.00",
       "currency": "ARS"
    },
    "requestType": "PaymentCardPreAuthTransaction",
    "storeId": "5912345678",
    "paymentMethod": {
       "paymentCard": {
          "number": "5165850000000008",
          "securityCode": "123",
          "expiryDate": {
             "month": "12",
             "year": "29"
          }
       }
    }
}
```

**Post auth:**

Para el proceso de post-auth simplemente debemos apuntar a el Endpoint:

```http
https://cert.api.firstdata.com/gateway/v2/payments/84533163643
```

*se debe sustituir 84533163643 por el valor devuelto en ipgTransactionId de la respuesta exitosa de la Pre-Auth que vamos a autorizar.

Payload:

```json
{
    "requestType": "PostAuthTransaction",
    "transactionAmount": {
       "total": "5.00",  "currency": "ARS"
    }
}
```

**Generación de Payment URL**

```json
{
    "transactionAmount": {
       "total": "100.00",
       "currency": "ARS"
    },
    "storeId": "5912345678",
    "transactionType": "SALE",
    "transactionNotificationURL": "https://www.firstdata.com/es_mx/home.html",
    "clientLocale": {
       "language": "es",
       "country": "AR"
    },
    "installmentOptions": {
       "numberOfInstallments": 6,
       "installmentsInterest": false
    }
}
```

## 8. Link de Pago (Payment URL)

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §8*

La Rest API de IPG permite generar URLs de pago de un solo uso que pueden ser distribuidas por un canal externo. Estas URL son generadas de forma dinámica y permiten al comercio distribuirlas a través de un canal externo como email, mensajes de texto, WhatsApp, etc. a sus clientes. La respuesta es un objeto JSON de tipo PaymentUrlResponse.

**Payment URL**

| Nombre de la transacción (Payload) | Descripción |
| --- | --- |
| PaymentUrlRequest | Crea una URL de un solo uso para concluir una venta. |

Adicionalmente, puede encontrar ejemplos armados del payload de Link de Pago en el Apéndice VI, “Transacciones comunes”.


---

# Parte 3 — Zero Auth

Validación de tarjeta sin importe, previa a la tokenización o al alta de un medio de pago.

## Zero Auth

*Fuente: Zero Auth 2.pdf*

Manual de integración

El presente documento está dirigido a los desarrolladores que utilizar la funcionalidad "Zero Auth" con la solución IPG de Fiserv en sistemas de e-commerce.

Para su total comprensión e interpretación se requieren conocimientos intermedios – avanzados sobre el consumo de servicios web. Así mismo, es importante que el desarrollador conozca por completo el lenguaje de programación que utilizará para implementar su solución.

El objetivo principal de este documento es guiar al desarrollador para que pueda probar la funcionalidad en ambiente Sandbox.

### Sumário

1. INTRODUCCIÓN — 3
2. PRIMEROS PASOS — 3
3. EJEMPLO API REST — 3
   - 3.1 Utilizando Pan — 3
   - 3.2 Utilizando Network Token — 4
   - 3.3 Utilizando Token Gateway — 4
4. EJEMPLO API SOAP — 5
   - 4.1 Utilizando Pan — 5
   - 4.2 Utilizando Network Token — 5
   - 4.3 Utilizando Token Gateway — 6
5. Puntos a considerar — 7

### 1. INTRODUCCIÓN

Zero Auth (también conocido como zero amount authorization) es una operación utilizada en el comercio electrónico para validar una tarjeta sin realizar un cargo real. Consiste en enviar una transacción con monto 0 al emisor de la tarjeta, con el objetivo de verificar que la tarjeta es válida, está activa y puede ser autorizada.

Este tipo de validación permite confirmar aspectos como la vigencia de la tarjeta, el estado de la cuenta y, en algunos casos, la coincidencia de datos como CVV o dirección, sin impactar el límite disponible del cliente ni generar movimientos financieros.

Zero Auth es comúnmente utilizado en procesos de alta de tarjetas (card-on-file), suscripciones o previos a una transacción real, ya que reduce el riesgo de rechazos posteriores y mejora la tasa de aprobación en pagos futuros.

En resumen, es una herramienta clave para validar tarjetas de manera segura y sin fricción antes de realizar un cobro efectivo.

### 2. PRIMEROS PASOS

Para realizar la validación Zero Auth, es fundamental contar con una integración funcional básica para ventas, ya que se utilizará la misma base. Si aún no dispones de esta integración, te recomendamos contactar al equipo de soporte para recibir los manuales adicionales necesarios para la integración deseada.

Para entender la posterior explicación, precisamos definir algunos campos dinámicos utilizados en las solicitudes:

- `{{card}}`: es el número de la tarjeta (PAN).
- `{{NetworkToken}}`: Es el número de token único provisto por las Banderas.
- `{{TokenGateway}}`: es el dato de referencia que substituirá el número de la tarjeta, es provisto por Fiserv.

### 3. EJEMPLO API REST

#### 3.1 Utilizando Pan

```json
{
    "transactionAmount": {
        "total": 0,
        "currency": "ARS"
    },
    "storeId" : "5923080904",
   "paymentMethod": {
       "paymentCard": {
         "number": {{card}},
         "securityCode": "123",
         "expiryDate": {
           "month": "12",
           "year": "29"
         }
      }
   },
    "requestType": "PaymentCardSaleTransaction"
}
```

#### 3.2 Utilizando Network Token

```json
{
   "requestType": "PaymentCardSaleTransaction",
   "storeId": "5923080904",
   "transactionAmount": {
      "total": "0",
      "currency": "ARS"
   },
   "paymentMethod": {
      "paymentCard": {
         "number": "{{NetworkToken}}",
         "expiryDate": {
           "month": "12",
           "year": "29"
         }
     }
   },
   "order": {
      "tokenCryptogram": "AgAAAAoAPlUosiUEDQNSgElQEAA="
   }
}
```

#### 3.3 Utilizando Token Gateway

```json
{
   "transactionAmount": {
      "total": "0",
      "currency": "ARS"
   },
   "storeId" : "5923080904",
   "requestType": "PaymentTokenSaleTransaction",
   "paymentMethod": {
       "paymentToken": {
         "tokenOriginStoreId": "5923080904",
         "value": “{{TokenGateway}}"
       }
   }
}
```

### 4. EJEMPLO API SOAP

#### 4.1 Utilizando Pan

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ipg="http://ipg-online.com/ipgapi/schemas/ipgapi" xmlns:v1="http://ipg-online.com/ipgapi/schemas/v1">
  <soapenv:Header/>
  <soapenv:Body>
     <ipg:IPGApiOrderRequest>
        <v1:Transaction>
          <v1:CreditCardTxType>
             <v1:StoreId>5923080904</v1:StoreId>
             <v1:Type>sale</v1:Type>
          </v1:CreditCardTxType>
          <v1:CreditCardData>
             <v1:CardNumber>{{card}}</v1:CardNumber>
             <v1:ExpMonth>12</v1:ExpMonth>
             <v1:ExpYear>29</v1:ExpYear>
             <v1:CardCodeValue>123</v1:CardCodeValue>
          </v1:CreditCardData>
          <v1:Payment>
             <v1:ChargeTotal>0</v1:ChargeTotal>
             <v1:Currency>032</v1:Currency>
          </v1:Payment>
        </v1:Transaction>
     </ipg:IPGApiOrderRequest>
  </soapenv:Body>
</soapenv:Envelope>
```

#### 4.2 Utilizando Network Token

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ipg="http://ipg-online.com/ipgapi/schemas/ipgapi" xmlns:v1="http://ipg-online.com/ipgapi/schemas/v1">
  <soapenv:Header/>
  <soapenv:Body>
    <ipg:IPGApiOrderRequest>
       <v1:Transaction>
         <v1:CreditCardTxType>
           <v1:StoreId>5923092899</v1:StoreId>
           <v1:Type>sale</v1:Type>
         </v1:CreditCardTxType>
         <v1:CreditCardData>
           <v1:CardNumber>{{NetworkToken}}</v1:CardNumber>
           <v1:ExpMonth>12</v1:ExpMonth>
           <v1:ExpYear>29</v1:ExpYear>
           <v1:CardCodeValue>123</v1:CardCodeValue>
         </v1:CreditCardData>
         <v1:TokenCryptogram>AgAAAAAAPljMzVcrSQ0pQCkAAAA=</v1:TokenCryptogram>
          <v1:Payment>
             <v1:ChargeTotal>0</v1:ChargeTotal>
             <v1:Currency>032</v1:Currency>
          </v1:Payment>
        </v1:Transaction>
     </ipg:IPGApiOrderRequest>
  </soapenv:Body>
</soapenv:Envelope>
```

#### 4.3 Utilizando Token Gateway

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ipg="http://ipg-online.com/ipgapi/schemas/ipgapi" xmlns:v1="http://ipg-online.com/ipgapi/schemas/v1">
  <soapenv:Header/>
  <soapenv:Body>
     <ipg:IPGApiOrderRequest>
        <v1:Transaction>
          <v1:CreditCardTxType>
            <v1:StoreId>5923080904</v1:StoreId>
            <v1:Type>sale</v1:Type>
          </v1:CreditCardTxType>
          <v1:CreditCardData>
            <v1:CardCodeValue>123</v1:CardCodeValue>
          </v1:CreditCardData>
          <v1:Payment>
            <v1:HostedDataID>visa1</v1:HostedDataID>
            <v1:HostedDataStoreID>5923080904</v1:HostedDataStoreID>
            <v1:ChargeTotal>0</v1:ChargeTotal>
            <v1:Currency>032</v1:Currency>
          </v1:Payment>
        </v1:Transaction>
     </ipg:IPGApiOrderRequest>
  </soapenv:Body>
</soapenv:Envelope>
```

### 5. Puntos a considerar

Para las consultas de tarjetas Mastercard deben agregarse los parámetros de DataOnly, por ejemplo:

#### API REST

```json
{
  "transactionAmount": {
     "total": "0",
     "currency": "ARS"
  },
  "requestType": "PaymentCardSaleTransaction",
  "storeId" : "5923080904",
  "paymentMethod": {
     "paymentCard": {
        "number": "{{card}}",
        "securityCode": "123",
        "expiryDate": {
           "month": "12",
           "year": "29"
        }
     }
  },
  "authenticationRequest": {
     "authenticationType": "Secure3DAuthenticationRequest",
     "messageCategory": "80",
     "methodNotificationURL" : "https://webhook.site/065191be-0702-46ae-a949-9b6730b4ac06",
     "termURL" : "https://webhook.site/065191be-0702-46ae-a949-9b6730b4ac06"
  }
}
```

#### API SOAP

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ipg="http://ipg-online.com/ipgapi/schemas/ipgapi" xmlns:v1="http://ipg-online.com/ipgapi/schemas/v1">
  <soapenv:Header/>
  <soapenv:Body>
     <ipg:IPGApiOrderRequest>
        <v1:Transaction>
          <v1:CreditCardTxType>
             <v1:StoreId>5923080904</v1:StoreId>
             <v1:Type>sale</v1:Type>
          </v1:CreditCardTxType>
          <v1:CreditCardData>
             <v1:CardNumber>{{card}}</v1:CardNumber>
             <v1:ExpMonth>12</v1:ExpMonth>
             <v1:ExpYear>29</v1:ExpYear>
             <v1:CardCodeValue>123</v1:CardCodeValue>
          </v1:CreditCardData>
          <v1:CreditCard3DSecure>
             <v1:AuthenticateTransaction>true</v1:AuthenticateTransaction>
             <v1:ThreeDSEmvCoMessageCategory>80</v1:ThreeDSEmvCoMessageCategory>
          </v1:CreditCard3DSecure>
          <v1:Payment>
             <v1:ChargeTotal>0</v1:ChargeTotal>
             <v1:Currency>032</v1:Currency>
          </v1:Payment>
        </v1:Transaction>
     </ipg:IPGApiOrderRequest>
  </soapenv:Body>
</soapenv:Envelope>
```


---

# Parte 4 — Tokenización

Tokens de IPG (gateway), tokenización Passthrough y Network Token de marca (MTRG).

## 9. Tokenización

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §9*

Los tokens son útiles para almacenar los detalles de los instrumentos de pago de un cliente, con el fin de asegurar y agilizar el proceso de pago en futuras transacciones. El proceso es el siguiente: cuando recopile los métodos de pago de un cliente, puede solicitar un token, el cual luego podrá usar en lugar de la tarjeta del cliente para ejecutar pagos futuros. Luego deberá almacenar el token y vincularlo a los detalles de la cuenta del cliente.

Asimismo, los tokens son útiles porque reducen el riesgo de que los ataques a sus sistemas de pago y a los nuestros tengan éxito. La tokenización también reduce el requisito de PCI para usted, ya que significa que no necesita almacenar los detalles de la tarjeta dentro de sus sistemas, lo que debería reducir sus costos asociados con el cumplimiento de PCI.

Las transacciones tokenizadas pueden enviarse mediante alguno de los siguientes flujos:

a. Tokenización IPG:
   a. Token de IPG
   b. Network Tokens
b. Tokenización Passthrough:
   a. Tokens externos (únicamente Network Tokens)

### 9.1 Tokenización IPG

IPG puede almacenar datos confidenciales del titular de la tarjeta en una base de datos cifrada en el centro de datos de Fiserv para usarlos en transacciones posteriores sin la necesidad de almacenar estos datos dentro de sus propios sistemas.

#### 9.1.1 Tipos de tokenización IPG

Existen dos niveles de tokenización que puede obtener mediante IPG:

b. **Token de IPG:**
   IPG almacena los datos de la tarjeta (número de tarjeta y fecha de vencimiento) en su Data Vault, ofreciendo un token (hosted data id) al comercio, para que realice las transacciones con él.

c. **Network Tokens:**
   Los tokens de red (network tokens) son aquellos generados por las marcas (VISA, MasterCard) quienes, en el proceso, resguardan la información de los tarjetahabientes, generando así transacciones más seguras.

   IPG cuenta con servicio de tokenización integrado que permite a un token de IPG (hosted data id) resguardar también un Network Token.

   Si desea transaccionar con networks tokens utilizando el servicio de tokenización integrado a IPG, debe solicitarlo expresamente a su equipo de soporte en Fiserv.

#### 9.1.2 Payloads básicos de tokenización

**Transacciones: tokenización IPG**

| Tipo de transacción (Payload) | Descripción |
| --- | --- |
| PaymentCardPaymentTokenizationRequest | Crea un token de pago en el servidor de IPG asociándolo a tu tienda. |
| PaymentTokenSaleTransaction | Realiza una venta con el token generado previamente. |
| PaymentTokenPreAuthTransaction | Realiza una preauth con el token generado previamente. |

#### 9.1.3 Parámetros mandatorios y opcionales

**Transacciones: PaymentCardPaymentTokenizationRequest**

| | |
| --- | --- |
| requestType (siempre mandatorio) | PaymentCardPaymentTokenizationRequest |
| Campos mandatorios | createToken/reusable<br>createToken/declineDuplicates<br>paymentMethod/paymentCard/number<br>paymentMethod/paymentCard/expiryDate |
| Campos opcionales * | createToken/ value<br>paymentMethod/paymentCard/securityCode |

\* Pueden sumarse el resto de los campos opcionales de las transacciones primarias (parámetros de billing, shipping, additionalDetails o cuotas).

**Transacciones: PaymentTokenSaleTransaction**

| | |
| --- | --- |
| requestType (siempre mandatorio) | PaymentTokenSaleTransaction |
| Campos mandatorios | paymentMethod/paymentToken/value<br>transactionAmount /total<br>transactionAmount/currency |
| Campos opcionales * | paymentMethod/paymentCard/securityCode |
| Campos que no aplican | paymentMethod/paymentCard/number<br>paymentMethod/paymentCard/expiryDate |

\* Pueden sumarse el resto de los campos opcionales de las transacciones primarias (parámetros de billing, shipping, additionalDetails o cuotas).

**Transacciones: PaymentTokenPreAuthTransaction**

| | |
| --- | --- |
| requestType (siempre mandatorio) | PaymentTokenPreAuthTransaction |
| Campos mandatorios | paymentMethod/paymentToken/value<br>transactionAmount /total<br>transactionAmount/currency |
| Campos opcionales * | paymentMethod/paymentCard/securityCode |
| Campos que no aplican | paymentMethod/paymentCard/number<br>paymentMethod/paymentCard/expiryDate |

\* Pueden sumarse el resto de los campos opcionales de las transacciones primarias (parámetros de billing, shipping, additionalDetails o cuotas).

#### 9.1.4 Tokens de IPG: transacciones

Los pagos puntuales (no recurrentes) realizados con tokens de IPG (hosted data id) deben realizarse de la siguiente forma:

##### 9.1.4.1 Generación del Token IPG

Request:

```json
{
    "requestType": "PaymentCardPaymentTokenizationRequest",
    "paymentCard": {
        "number": "4044710000000004",
        "expiryDate": {
            "month": "12",
            "year": "29"
        }
    },
    "createToken": {
        "reusable": true,
        "declineDuplicates": false
    }
}
```

Response:

```json
{
    "type": "paymentTokenizationResponse",
    "clientRequestId": "2a44b332-b69d-434d-ba89-e660e5df3edf",
    "apiTraceId": "aEX6fcjjjbepc9KUCHB5bwAAAp0",
    "requestStatus": "SUCCESS",
    "requestTime": 1749416573927,
    "country": "Argentina",
    "paymentToken": {
        "value": "F57CF893-086C-4DE9-B7EC-9739670308E7",
        "reusable": true,
        "declineDuplicates": false,
        "last4": "0005",
        "brand": "VISA",
        "type": "NETWORK_TOKEN",
        "networkTokenProvisionStatus": "PROVISIONED"
    },
    "orderId": "R-b54b502e-c959-4aa2-bad2-ea3684034c38",
    "ipgTransactionId": "84618147419"
}
```

\*En el response anterior, el valor "F57CF893-086C-4DE9-B7EC-9739670308E7" corresponde al token de IPG, también llamado Hosted Data ID.

##### 9.1.4.2 Transacciones con el Token IPG

VISA:

```json
{
    "transactionAmount": {
        "total": "50.00",
        "currency": "ARS"
    },
    "storeId" : "5923080904",
    "requestType": "PaymentTokenSaleTransaction",
    "paymentMethod": {
        "paymentToken": {
            "tokenOriginStoreId": "5923080904",
            "value": "F57CF893-086C-4DE9-B7EC-9739670308E7"
        }
    }
}
```

MasterCard:

```json
{
    "storeId": "5923080904",
    "requestType": "PaymentTokenSaleTransaction",
    "transactionAmount": {
        "total": "5.00",
        "currency": "ARS"
    },
    "paymentMethod": {
        "paymentToken": {
            "value": "F57CF893-086C-4DE9-B7EC-9739670308E7",
            "tokenOriginStoreId": "5923080904"
        }
    },
    "storedCredentials": {
        "sequence": "FIRST",
        "scheduled": false,
        "initiator": "CARDHOLDER",
        "indicatorSubcategory": "STANDING_ORDER"
    }
}
```

##### 9.1.4.3 Tokenización y Card on File

Las transacciones tokenizadas forman parte del modelo conocido como Card on File (CoF), en el cual los datos de la tarjeta del cliente han sido previamente almacenados de forma segura en una base de datos, generalmente mediante un proceso de tokenización. Esto permite que futuras transacciones se realicen sin necesidad de ingresar nuevamente los datos de la tarjeta, mejorando la experiencia del usuario y reduciendo la fricción en el proceso de pago. Este enfoque es común en plataformas de ecommerce que ofrecen pagos recurrentes o compras con un solo clic.

**Tipos de transacciones: CIT y MIT**

Dentro del esquema Card on File, las transacciones pueden clasificarse en dos tipos principales: CIT (Cardholder Initiated Transaction) y MIT (Merchant Initiated Transaction). Las CIT son aquellas iniciadas directamente por el titular de la tarjeta, como cuando un usuario realiza una compra desde el sitio web o aplicación del comercio. En cambio, las MIT son iniciadas por el comercio sin la intervención directa del cliente en ese momento, como en el caso de suscripciones, pagos recurrentes o cobros por servicios previamente autorizados. Esta distinción es clave para el cumplimiento normativo y para el correcto tratamiento de las transacciones por parte de los adquirentes y emisores.

En el caso anterior, al tratarse de una transacción tokenizada que fue iniciada por el tarjetahabiente, debe informarse el parámetro CIT, correspondiente a la mensajería de este tipo de transacciones. Por ahora, este parámetro está disponible para la marca **Mastercard**.

### 9.2 Tokenización Passthrough

Los comercios que cuentan con servicios de tokenización propios o de terceros, ajenos a Fiserv y a IPG, también puede enviarnos sus transacciones así tokenizadas adicionando mensajería especial, siempre que esta tokenización sea la tokenización de marca (Network Tokens).

Los network tokens (también denominados "tokens de marca") son aquellos generados por las marcas (VISA, MasterCard) quienes, en el proceso, resguardan la información de los tarjetahabientes generando así, transacciones más seguras.

Cuando el PAN está tokenizado en la red, puede usarse en todo el ecosistema de pago, sin necesidad de actualizarse aún si la tarjeta estuviese, por ejemplo, vencida o robada.

Los tokens cuentan con período de utilidad definido por la Marca, el mismo dejará de ser válido en caso de encontrarse fuera de la fecha de vencimiento asignada o en casos en que la marca decidiese su baja temprana por fraude asociado al Token.

IPG permite gestionar las solicitudes de autorización en las que el token y el criptograma se hayan generado a partir de un proveedor de servicios de token externo o a través de la conectividad directa de los comerciantes a las redes. En este modelo, IPG actuará como modelo de paso, simplemente pasará los datos relacionados con el token de red a los emisores.

Este marco tiene como objetivo proporcionar un conjunto consistente y verificable de datos de transacciones que pueden aumentar la confianza y facilitar las decisiones de riesgo que pueden ayudar a aumentar las tasas de aprobación.

Los pagos puntuales (no recurrentes) realizados con Network Tokenization Passthrough deben enviarse de la siguiente forma, teniendo en cuenta que las transacciones con la marca Mastercard requieren un campo adicional:

VISA:

```json
{
    "requestType": "PaymentCardSaleTransaction",
    "storeId": "5923080904",
    "transactionAmount": {
        "total": "102.00",
        "currency": "ARS"
    },
    "paymentMethod": {
        "paymentCard": {
            "number": "4044710000000004",
            "expiryDate": {
                "month": "12",
                "year": "29"
            }
        }
    },
    "order": {
        "tokenCryptogram": "AgAAAAoAPlUosiUEDQNSgElQEAA="
    }
}
```

MasterCard:

```json
{
    "requestType": "PaymentCardSaleTransaction",
    "storeId": "5923080904",
    "transactionAmount": {
        "total": "102.00",
        "currency": "ARS"
    },
    "paymentMethod": {
        "paymentCard": {
            "number": "5165850000000008",
            "expiryDate": {
                "month": "12",
                "year": "29"
            }
        }
    },
    "storedCredentials": {
        "sequence": "FIRST",
        "scheduled": false,
        "initiator": "CARDHOLDER",
        "indicatorSubcategory": "STANDING_ORDER"
    },
    "order": {
        "tokenCryptogram": "AgAAAAoAPlUosiUEDQNSgElQEAA="
    }
}
```

Ejemplo de respuesta para una transacción con Network Tokenization:

```json
{
    "clientRequestId": "3ea5acbe-2fcf-42f6-9fce-0b34e435d015",
    "apiTraceId": "ZVUcGnNn3m0878N3vMgimgAAAtE",
    "ipgTransactionId": "84641795060",
    "orderId": "3210000",
    "transactionType": "SALE",
    "paymentToken": {
        "reusable": true,
        "declineDuplicates": false,
        "brand": "MASTERCARD",
        "type": "PAYMENT_CARD"
    },
    "transactionOrigin": "ECOM",
    "paymentMethodDetails": {
        "paymentCard": {
            "expiryDate": {
                "month": "12",
                "year": "2029"
            },
            "bin": "516585",
            "last4": "0008",
            "brand": "MASTERCARD"
        },
        "paymentMethodType": "PAYMENT_CARD",
        "paymentMethodBrand": "MASTERCARD"
    },
    "country": "Argentina",
    "terminalId": "98000000",
    "merchantId": "24000000",
    "transactionTime": 1700076570,
    "approvedAmount": {
        "total": 110.00,
        "currency": "ARS",
        "components": {
            "subtotal": 110.00
        }
    },
    "transactionAmount": {
        "total": 110.00,
        "currency": "ARS",
        "components": {
            "subtotal": 110.00
        }
    },
    "transactionStatus": "APPROVED",
    "approvalCode": "Y:855872:4641795060:PPXX:8558725039",
    "processor": {
        "referenceNumber": "855872855872",
        "authorizationCode": "855872",
        "responseCode": "00",
        "responseMessage": "Function performed error-free",
        "avsResponse": {
            "streetMatch": "NO_INPUT_DATA",
            "postalCodeMatch": "NO_INPUT_DATA"
        },
        "securityCodeResponse": "NOT_CHECKED"
    }
}
```

Los campos que deben modificar su mensajería para Network Tokenization Passthrough son:

| Parámetro | XML Scheme Type | Valor | Observaciones |
| --- | --- | --- | --- |
| CardNumber | xs:string | Token number.<br>= 16 characters<br>Example: 5249451254674815 | Debe viajar el Token, que contará con 16 números como el PAN de una tarjeta |
| ExpMonth | xs:string | Token expiration month.<br>Example: 10 | Debe especificarse en qué mes vence el Token |
| ExpYear | xs:string | Token expiration year.<br>Example: 22 | Se debe detallar el año en el que expira el Token |
| TokenCryptogram | xs:string | Cryptogram associated<br>Example: AgAAAAoAPlUosiUEDQNSgElQEAA= | Criptograma asociado al Token en cada transacción. Se enviará en Base64. |

\* El parámetro CardCodeValue no será requerido.

## Network Token (MTRG)

*Fuente: Manual NetworkToken MTRG.pdf*

> **Código de colores recuperado.** El manual resalta los parámetros con tres colores que no sobreviven a la extracción de texto. Se recuperaron leyendo los rectángulos de resaltado del PDF:
>
> | Color | Significado | Campos que marca |
> |---|---|---|
> | Verde | Parámetros de **NetworkToken** | `Bin` / `Last4` de nivel superior, `HostedDataType: NETWORK_TOKEN`, `NetworkTokenProvisionStatus`, `type: "NETWORK_TOKEN"`, `requestStatus` |
> | Amarillo | Parámetros de **PAN** | `CardNumber`, `ExpMonth`, `ExpYear`, `CardCodeValue`, `FundingCardNumberBin`, `FundingCardNumberLast4` |
> | Celeste | **HostedDataID** | `HostedDataID`, `HostedDataStoreID`, `AssignToken`, `tokenOriginStoreId`, `paymentToken.value` |
>
> **⚠ Contradicción en el manual.** En el ejemplo REST del flujo OnTheGo (pág. 11 del PDF) el resaltado está invertido respecto del ejemplo SOAP equivalente (pág. 6) y del ejemplo REST asíncrono (pág. 15): marca `fundingCardNumber.bin/last4` (462294 / 2358) como NetworkToken y `bin`/`last4` de nivel superior (489537 / 5144) como PAN. Por el significado del campo y por los otros dos ejemplos, la lectura correcta es la inversa:
>
> - `paymentMethodDetails.paymentCard.fundingCardNumber.{bin,last4}` → **PAN original**
> - `paymentMethodDetails.paymentCard.{bin,last4}` → **Network Token**
>
> Esto importa porque §2 del manual obliga a guardar el emparejamiento entre ambos pares en cada transacción aprobada. Confirmar con Fiserv antes de persistir los datos.

Manual de integración — NetworkToken MTRG

El presente documento está dirigido a los desarrolladores que desean integrar Network Token como método de pago en IPG de Fiserv.

Para su total comprensión e interpretación se requieren conocimientos intermedios – avanzados sobre el consumo de nuestra API. Así mismo, es importante que el desarrollador conozca por completo el lenguaje de programación que utilizará para implementar su solución.

El objetivo principal de este documento es guiar al desarrollador para que consiga realizar la integración en un entorno de pruebas (Sandbox) para posteriormente realizar la homologación y procesar estas vendas en ambiente productivo.

### Contenido

Sumário

1. Introducción — 3
2. Aspectos a considerar — 3
3. Primeros Pasos — 3
4. Ejemplos API SOAP — 4
   - a. Flujo OnTheGo — 4
   - b. Flujo asíncrono crear token — 6
   - a. Flujo asíncrono realizar pago — 8
5. Ejemplos API REST — 10
   - a. Flujo OnTheGo — 10
   - b. Flujo asíncrono crear token — 12
   - c. Flujo asíncrono realizar pago — 14

### 1. Introducción

Los Network Tokens son una tecnología innovadora que reemplaza el número de cuenta principal (PAN) de una tarjeta de crédito o débito con un token único y seguro para transacciones en línea. Este servicio es ofrecido por redes de tarjetas como Mastercard y Visa, y está diseñado para mejorar la seguridad y la eficiencia de los pagos digitales.

Uno de los principales beneficios de los Network Tokens es su capacidad de actualización automática. Si los datos de la tarjeta cambian, como en el caso de una renovación, el token se actualiza automáticamente, eliminando la necesidad de que los clientes actualicen manualmente su información en cada sitio web o aplicación. Esto no solo mejora la seguridad, sino que también reduce el número de transacciones rechazadas debido a credenciales obsoletas, aumentando así la tasa de autorización de pagos.

### 2. Aspectos a considerar

Algunos aspectos específicos de esta operatoria deben ser considerados antes de realizar la integración:

- **Compatibilidad de banderas:** El Network token solo es compatibles con las tarjetas Visa y Mastercard.
- **Uso obligatorio de VISA:** Todas las transacciones realizadas con tarjetas Visa, deben utilizar Network Token.
- **Dato de procesamiento:** Cuando se realiza una transacción con Network Token, el procesamiento se lleva a cabo mediante el Network Token. Esto significa que, en caso de desconocimiento de compras o para realizar la conciliación, recibirán el número del Network Token y no el número PAN. Por ello, es necesario que en cada transacción aprobada se realice un emparejamiento entre el Network Token y BIN + últimos 4 dígitos de la tarjeta original, para poder identificar qué transacción se realizó con cada tarjeta.

### 3. Primeros Pasos

Para realizar operaciones con NetworkToken, es fundamental contar con una integración funcional básica para ventas, ya que se utilizará la misma base. Si aún no dispones de esta integración, te recomendamos contactar al equipo de soporte para recibir los manuales adicionales necesarios para la integración deseada.

Para entender la posterior explicación, precisamos definir algunos conceptos:

- **HostedDataID:** es el dato de referencia que substituirá el número de la tarjeta al realizar la transacción.
- **NetworkToken:** Es el número de token único provisto por las Banderas.
- **OnTheGo:** Flujo que utiliza el PAN en la request de la transacción para procesar el pago con NetworkToken. El NetworkToken es provisto instantáneamente.
- **Asíncrono:** Flujo que utiliza un token de Gateway (HostedDataID) en la request de la transacción para procesar el pago con NetworkToken. El NetworkToken es provisto en hasta 20 segundos.

### 4. Ejemplos API SOAP

Para la integración con API SOAP es muy importante que sea respetado el orden de los parámetros tal como compartimos en los ejemplos ya que colocarlos en otro orden podrá generar errores.

Para una mejor visualización de los parámetros, resaltamos los mismos con colores específicos:

- Parámetros de NetworkToken
- Parámetros de PAN
- HostedDataID

> **[Imagen/diagrama en el documento original]** — recuadros de color que identifican los tres grupos de parámetros (NetworkToken, PAN, HostedDataID); el resaltado por color no se preserva en esta conversión.

#### a. Flujo OnTheGo

Este ejemplo corresponde al flujo denominado "OnTheGo" el comercio envía la request con los datos de la tarjeta (PAN, Venc, CVV), Fiserv solicita el NetworkToken y realiza la transacción con el mismo.

Cuando la transacción es aprobada el comercio guardará el BIN +4 últimos de la tarjeta y BIN y 4 últimos del Network Token (que vendrán en la respuesta de la transacción.

Request

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ipg="http://ipg-online.com/ipgapi/schemas/ipgapi" xmlns:v1="http://ipg-online.com/ipgapi/schemas/v1">
  <soapenv:Header/>
  <soapenv:Body>
     <ipg:IPGApiOrderRequest>
        <v1:Transaction>
          <v1:CreditCardTxType>
             <v1:StoreId>5923080904</v1:StoreId>
             <v1:Type>sale</v1:Type>
          </v1:CreditCardTxType>
          <v1:CreditCardData>
             <v1:CardNumber>{{CardNumber}}</v1:CardNumber>
             <v1:ExpMonth>12</v1:ExpMonth>
             <v1:ExpYear>29</v1:ExpYear>
             <v1:CardCodeValue>123</v1:CardCodeValue>
          </v1:CreditCardData>
          <v1:Payment>
             <v1:ChargeTotal>19.00</v1:ChargeTotal>
             <v1:Currency>032</v1:Currency>
          </v1:Payment>
        </v1:Transaction>
     </ipg:IPGApiOrderRequest>
  </soapenv:Body>
</soapenv:Envelope>
```

Response

```xml
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Header/>
  <SOAP-ENV:Body>
     <ipgapi:IPGApiOrderResponse xmlns:a1="http://ipg-online.com/ipgapi/schemas/a1" xmlns:ipgapi="http://ipg-online.com/ipgapi/schemas/ipgapi" xmlns:v1="http://ipg-online.com/ipgapi/schemas/v1">
        <ipgapi:ApprovalCode>Y:907885:4613679313:PPXX:9078859078</ipgapi:ApprovalCode>
        <ipgapi:AVSResponse>PPX</ipgapi:AVSResponse>
        <ipgapi:Brand>VISA</ipgapi:Brand>
        <ipgapi:Country>IND</ipgapi:Country>
        <ipgapi:CommercialServiceProvider>FDCS</ipgapi:CommercialServiceProvider>
        <ipgapi:ExternalMerchantID>9900004</ipgapi:ExternalMerchantID>
        <ipgapi:OrderId>A-61e17a0a-24a8-4fcd-9efe-dab7cb7dec6d</ipgapi:OrderId>
        <ipgapi:IpgTransactionId>84613679313</ipgapi:IpgTransactionId>
        <ipgapi:PaymentType>CREDITCARD</ipgapi:PaymentType>
        <ipgapi:ProcessorApprovalCode>907885</ipgapi:ProcessorApprovalCode>
        <ipgapi:ProcessorReceiptNumber>9078</ipgapi:ProcessorReceiptNumber>
        <ipgapi:ProcessorBatchNumber>001</ipgapi:ProcessorBatchNumber>
        <ipgapi:ProcessorEndpointID>TXSP ARGENTINA VIA CAFEX VISA</ipgapi:ProcessorEndpointID>
        <ipgapi:ProcessorCCVResponse>X</ipgapi:ProcessorCCVResponse>
        <ipgapi:ProcessorReferenceNumber>907885907885</ipgapi:ProcessorReferenceNumber>
        <ipgapi:ProcessorResponseCode>00</ipgapi:ProcessorResponseCode>
        <ipgapi:ProcessorAssociationResponseCode>XX</ipgapi:ProcessorAssociationResponseCode>
        <ipgapi:ProcessorResponseMessage>Function performed error-free</ipgapi:ProcessorResponseMessage>
        <ipgapi:ProcessorTraceNumber>907885</ipgapi:ProcessorTraceNumber>
        <ipgapi:TDate>1745415495</ipgapi:TDate>
        <ipgapi:TDateFormatted>2025.04.23 15:38:15 (CEST)</ipgapi:TDateFormatted>
        <ipgapi:TerminalID>98000005</ipgapi:TerminalID>
        <ipgapi:TransactionResult>APPROVED</ipgapi:TransactionResult>
        <ipgapi:TransactionDeclineReason>New account information available</ipgapi:TransactionDeclineReason>
        <ipgapi:TransactionTime>1745415495</ipgapi:TransactionTime>
        <ipgapi:MerchantAdviceCode>01</ipgapi:MerchantAdviceCode>
        <ipgapi:MerchantAdviceCodeIndicator>01</ipgapi:MerchantAdviceCodeIndicator>
        <ipgapi:Bin>489537</ipgapi:Bin>
        <ipgapi:Last4>5144</ipgapi:Last4>
        <ipgapi:FundingCardNumberBin>462294</ipgapi:FundingCardNumberBin>
        <ipgapi:FundingCardNumberLast4>2358</ipgapi:FundingCardNumberLast4>
     </ipgapi:IPGApiOrderResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

#### b. Flujo asíncrono crear token

Este ejemplo corresponde al flujo denominado "Asíncrono" el comercio solicita para Fiserv la creación de un NetworkToken, Fiserv solicita la generación de un Network Token y devuelve al comercio un HostedDataID.

La transacción se realiza con el HostedDataID en lugar de los datos de la tarjeta.

Cuando la transacción es aprobada el comercio guardará el BIN +4 últimos de la tarjeta y BIN y 4 últimos del Network Token (que vendrán en la respuesta de la transacción.

Request de generación de HostedDataID Personalizado

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ipg="http://ipg-online.com/ipgapi/schemas/ipgapi" xmlns:v1="http://ipg-online.com/ipgapi/schemas/a1" xmlns:v2="http://ipg-online.com/ipgapi/schemas/v1">
  <soapenv:Header/>
  <soapenv:Body>
     <ipg:IPGApiActionRequest>
        <v1:Action>
          <v1:StoreHostedData>
            <v1:StoreId>5923080904</v1:StoreId>
            <v1:DataStorageItem>
               <v1:CreditCardData>
                  <v2:CardNumber>{{CardNumber}}</v2:CardNumber>
                  <v2:ExpMonth>12</v2:ExpMonth>
                  <v2:ExpYear>29</v2:ExpYear>
               </v1:CreditCardData>
               <v1:HostedDataID>visa1</v1:HostedDataID>
            </v1:DataStorageItem>
          </v1:StoreHostedData>
        </v1:Action>
     </ipg:IPGApiActionRequest>
  </soapenv:Body>
</soapenv:Envelope>
```

Response

```xml
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Header/>
  <SOAP-ENV:Body>
     <ipgapi:IPGApiActionResponse xmlns:a1="http://ipg-online.com/ipgapi/schemas/a1" xmlns:ipgapi="http://ipg-online.com/ipgapi/schemas/ipgapi" xmlns:v1="http://ipg-online.com/ipgapi/schemas/v1">
        <ipgapi:successfully>true</ipgapi:successfully>
     </ipgapi:IPGApiActionResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

Request de generación de HostedDataID padrón

Request

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ipg="http://ipg-online.com/ipgapi/schemas/ipgapi" xmlns:v1="http://ipg-online.com/ipgapi/schemas/a1" xmlns:v2="http://ipg-online.com/ipgapi/schemas/v1">
  <soapenv:Header/>
  <soapenv:Body>
     <ipg:IPGApiActionRequest>
        <v1:Action>
          <v1:StoreHostedData>
            <v1:StoreId>5923080904</v1:StoreId>
            <v1:DataStorageItem>
               <v1:CreditCardData>
                  <v2:CardNumber>{{CardNumber}}</v2:CardNumber>
                  <v2:ExpMonth>12</v2:ExpMonth>
                  <v2:ExpYear>29</v2:ExpYear>
               </v1:CreditCardData>
               <v1:AssignToken>true</v1:AssignToken>
            </v1:DataStorageItem>
          </v1:StoreHostedData>
        </v1:Action>
     </ipg:IPGApiActionRequest>
  </soapenv:Body>
</soapenv:Envelope>
```

Response

```xml
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Header/>
  <SOAP-ENV:Body>
     <ipgapi:IPGApiActionResponse xmlns:a1="http://ipg-online.com/ipgapi/schemas/a1" xmlns:ipgapi="http://ipg-online.com/ipgapi/schemas/ipgapi" xmlns:v1="http://ipg-online.com/ipgapi/schemas/v1">
        <ipgapi:successfully>true</ipgapi:successfully>
        <ipgapi:DataStorageItem>
           <a1:CreditCardData>
             <v1:CardNumber>0005</v1:CardNumber>
             <v1:ExpMonth>12</v1:ExpMonth>
             <v1:ExpYear>29</v1:ExpYear>
             <v1:Brand>VISA</v1:Brand>
           </a1:CreditCardData>
           <a1:HostedDataID>E20455AC-CFB2-4229-84C3-99538EE9215C</a1:HostedDataID>
           <a1:HostedDataType>NETWORK_TOKEN</a1:HostedDataType>
           <a1:NetworkTokenProvisionStatus>PROVISIONED</a1:NetworkTokenProvisionStatus>
           <a1:cardFunction>credit</a1:cardFunction>
        </ipgapi:DataStorageItem>
     </ipgapi:IPGApiActionResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

#### a. Flujo asíncrono realizar pago

Request

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ipg="http://ipg-online.com/ipgapi/schemas/ipgapi" xmlns:v1="http://ipg-online.com/ipgapi/schemas/v1">
  <soapenv:Header/>
  <soapenv:Body>
     <ipg:IPGApiOrderRequest>
        <v1:Transaction>
          <v1:CreditCardTxType>
            <v1:StoreId>5923080904</v1:StoreId>
            <v1:Type>sale</v1:Type>
          </v1:CreditCardTxType>
          <v1:CreditCardData>
          </v1:CreditCardData>
          <v1:Payment>
             <v1:HostedDataID>51CA238C-256F-432C-87C4-A53FF11A883C</v1:HostedDataID>
             <v1:HostedDataStoreID>5923080904</v1:HostedDataStoreID>
             <v1:ChargeTotal>500</v1:ChargeTotal>
             <v1:Currency>032</v1:Currency>
          </v1:Payment>
        </v1:Transaction>
     </ipg:IPGApiOrderRequest>
  </soapenv:Body>
</soapenv:Envelope>
```

Response

```xml
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
   <SOAP-ENV:Header/>
   <SOAP-ENV:Body>
     <ipgapi:IPGApiOrderResponse xmlns:a1="http://ipg-online.com/ipgapi/schemas/a1" xmlns:ipgapi="http://ipg-online.com/ipgapi/schemas/ipgapi" xmlns:v1="http://ipg-online.com/ipgapi/schemas/v1">
        <ipgapi:ApprovalCode>Y:367904:4681091005:PPXX:3679049872</ipgapi:ApprovalCode>
        <ipgapi:AVSResponse>PPX</ipgapi:AVSResponse>
        <ipgapi:Brand>MASTERCARD</ipgapi:Brand>
        <ipgapi:CommercialServiceProvider>FDCS</ipgapi:CommercialServiceProvider>
        <ipgapi:ExternalMerchantID>9900004</ipgapi:ExternalMerchantID>
        <ipgapi:OrderId>A-deb046c2-17a0-4539-891f-c4f593a94d3c</ipgapi:OrderId>
        <ipgapi:IpgTransactionId>84681091005</ipgapi:IpgTransactionId>
        <ipgapi:PaymentType>CREDITCARD</ipgapi:PaymentType>
        <ipgapi:ProcessorApprovalCode>367904</ipgapi:ProcessorApprovalCode>
        <ipgapi:ProcessorReceiptNumber>9872</ipgapi:ProcessorReceiptNumber>
        <ipgapi:ProcessorBatchNumber>001</ipgapi:ProcessorBatchNumber>
        <ipgapi:ProcessorEndpointID>TXSP ARGENTINA VIA CAFEX VISA</ipgapi:ProcessorEndpointID>
        <ipgapi:ProcessorCCVResponse>X</ipgapi:ProcessorCCVResponse>
        <ipgapi:ProcessorReferenceNumber>367904367904</ipgapi:ProcessorReferenceNumber>
        <ipgapi:ProcessorResponseCode>00</ipgapi:ProcessorResponseCode>
        <ipgapi:ProcessorAssociationResponseCode>XX</ipgapi:ProcessorAssociationResponseCode>
        <ipgapi:ProcessorResponseMessage>Function performed error-free</ipgapi:ProcessorResponseMessage>
        <ipgapi:ProcessorTraceNumber>367904</ipgapi:ProcessorTraceNumber>
        <ipgapi:TDate>1743448822</ipgapi:TDate>
        <ipgapi:TDateFormatted>2025.03.31 21:20:22 (CEST)</ipgapi:TDateFormatted>
        <ipgapi:TerminalID>98000009</ipgapi:TerminalID>
        <ipgapi:TransactionResult>APPROVED</ipgapi:TransactionResult>
        <ipgapi:TransactionDeclineReason>New account information available</ipgapi:TransactionDeclineReason>
        <ipgapi:TransactionTime>1743448822</ipgapi:TransactionTime>
        <ipgapi:MerchantAdviceCode>01</ipgapi:MerchantAdviceCode>
        <ipgapi:MerchantAdviceCodeIndicator>01</ipgapi:MerchantAdviceCodeIndicator>
        <ipgapi:ProcessorPromotionalMessage>03/25</ipgapi:ProcessorPromotionalMessage>
        <ipgapi:Bin>520424</ipgapi:Bin>
        <ipgapi:Last4>7793</ipgapi:Last4>
        <ipgapi:FundingCardNumberBin>520424</ipgapi:FundingCardNumberBin>
        <ipgapi:FundingCardNumberLast4>3013</ipgapi:FundingCardNumberLast4>
     </ipgapi:IPGApiOrderResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

### 5. Ejemplos API REST

Para una mejor visualización de los parámetros, resaltamos los mismos con colores específicos:

- Parámetros de NetworkToken
- Parámetros de PAN
- HostedDataID

> **[Imagen/diagrama en el documento original]** — recuadros de color que identifican los tres grupos de parámetros (NetworkToken, PAN, HostedDataID); el resaltado por color no se preserva en esta conversión.

#### a. Flujo OnTheGo

Este ejemplo corresponde al flujo denominado "OnTheGo" el comercio envía la request con los datos de la tarjeta (PAN, Venc, CVV), Fiserv solicita el NetworkToken y realiza la transacción con el mismo.

Cuando la transacción es aprobada el comercio guardará el BIN +4 últimos de la tarjeta y BIN y 4 últimos del Network Token (que vendrán en la respuesta de la transacción.

Request

```json
{
  "transactionAmount": {
      "total": 10,
      "currency": "ARS"
  },
  "storeId" : "5923080904",
  "paymentMethod": {
      "paymentCard": {
         "number": {{CardNumber}},
         "securityCode": "123",
         "expiryDate": {
            "month": "12",
            "year": "29"
         }
      }
  },
  "requestType": "PaymentCardSaleTransaction"
}
```

Response

```json
{
    "type": "transactionResponse",
    "clientRequestId": "f2c70353-28a6-4f3a-8eb6-0cbc0a8eceab",
    "apiTraceId": "aAjzoKYzVN_vOAh4zcTWHAAAAqU",
    "ipgTransactionId": "84613681050",
    "orderId": "R-d21a578f-7e81-4956-ab63-c5a04e47bcbb",
    "transactionType": "SALE",
    "paymentToken": {
       "reusable": true,
       "declineDuplicates": false,
       "brand": "VISA",
       "type": "PAYMENT_CARD"
    },
    "transactionOrigin": "ECOM",
    "paymentMethodDetails": {
       "paymentCard": {
          "expiryDate": {
             "month": "12",
             "year": "2030"
          },
          "fundingCardNumber": {
             "bin": "462294",
             "last4": "2358"
          },
          "bin": "489537",
          "last4": "5144",
          "brand": "VISA"
       },
       "paymentMethodType": "PAYMENT_CARD",
       "paymentMethodBrand": "VISA"
    },
    "country": "India",
    "terminalId": "98000009",
    "merchantId": "9900004",
    "transactionTime": 1745417121,
    "approvedAmount": {
       "total": 10.00,
       "currency": "ARS",
       "components": {
          "subtotal": 10.00
       }
    },
    "transactionAmount": {
       "total": 10.00,
       "currency": "ARS",
       "components": {
          "subtotal": 10.00
       }
    },
    "transactionStatus": "APPROVED",
    "approvalCode": "Y:908651:4613681050:PPXX:9086510849",
    "processor": {
       "referenceNumber": "908651908651",
       "authorizationCode": "908651",
       "responseCode": "00",
       "associationResponseCode": "XX",
       "responseMessage": "Function performed error-free",
       "avsResponse": {
          "streetMatch": "NO_INPUT_DATA",
          "postalCodeMatch": "NO_INPUT_DATA"
       },
       "securityCodeResponse": "NOT_CHECKED",
       "merchantAdviceCodeIndicator": "01",
       "taxRefundData": {}
    }
}
```

#### b. Flujo asíncrono crear token

Este ejemplo corresponde al flujo denominado "Asíncrono" el comercio solicita para Fiserv la creación de un NetworkToken, Fiserv solicita la generación de un Network Token y devuelve al comercio un HostedDataID.

La transacción se realiza con el HostedDataID en lugar de los datos de la tarjeta.

Cuando la transacción es aprobada el comercio guardará el BIN +4 últimos de la tarjeta y BIN y 4 últimos del Network Token (que vendrán en la respuesta de la transacción.

Request de generación de HostedDataID Personalizado

```json
{
    "requestType": "PaymentCardPaymentTokenizationRequest",
    "storeId" : 5923080904,
    "paymentCard": {
          "number": "{{CardNumber}}",
          "expiryDate": {
            "month": "12",
            "year": "29"
          }
       },
    "createToken": {
       "value": "nombre_del_token",
       "reusable": true,
       "declineDuplicates": false
    }
}
```

Response

```json
{
    "type": "paymentTokenizationResponse",
    "clientRequestId": "0f9d39a8-9c02-4e04-821d-6c0599525594",
    "apiTraceId": "Z-rtIl8TKpVqzf_73IO_2QAAApY",
    "requestStatus": "SUCCESS",
    "requestTime": 1743449378393,
    "paymentToken": {
       "value": "nombre_del_token",
       "reusable": true,
       "declineDuplicates": false,
       "last4": "3013",
       "brand": "MASTERCARD",
       "type": "NETWORK_TOKEN",
       "networkTokenProvisionStatus": "PROVISIONED"
    },
    "orderId": "R-ffc24591-58be-4a66-b18b-4e25c00945bc",
    "ipgTransactionId": "84681091628"
}
```

Request de generación de HostedDataID padrón.

```json
{
    "requestType": "PaymentCardPaymentTokenizationRequest",
    "storeId" : 5923080904,
    "paymentCard": {
          "number": "{{CardNumber}}",
          "expiryDate": {
            "month": "12",
            "year": "29"
          }
       },
    "createToken": {
       "reusable": true,
       "declineDuplicates": false
    }
}
```

Response

```json
{
  "type": "paymentTokenizationResponse",
  "clientRequestId": "c39278c0-826c-4d59-b450-1285f81b3148",
  "apiTraceId": "Z-r4HI8fwtGevDN8Dl22gwAAAzg",
  "requestStatus": "SUCCESS",
  "requestTime": 1743452188521,
  "paymentToken": {
     "value": "96DCAB40-0110-4821-9230-F852720DCC98",
     "reusable": true,
     "declineDuplicates": false,
     "last4": "3013",
     "brand": "MASTERCARD",
     "type": "NETWORK_TOKEN",
     "networkTokenProvisionStatus": "PROVISIONED"
  },
  "orderId": "R-9d34b7b8-09c1-49d4-8009-240ae08a3cf9",
  "ipgTransactionId": "84681094144"
}
```

#### c. Flujo asíncrono realizar pago

El ultimo paso será realizar la transacción utilizando el NetworkToken, como en el siguiente ejemplo:

Request

```json
{
    "transactionAmount": {
       "total": "10.00",
       "currency": "ARS"
    },
    "storeId" : "5923080904",
    "requestType": "PaymentTokenSaleTransaction",
    "paymentMethod": {
       "paymentToken": {
         "tokenOriginStoreId": "5923080904",
         "value": "96DCAB40-0110-4821-9230-F852720DCC98"
       }
    }
}
```

Response

```json
{
  "type": "transactionResponse",
  "clientRequestId": "47391231-cc02-4062-82dd-7823698f21b2",
  "apiTraceId": "Z-r5jDU3q-ps32M0llj5JQAAA8k",
  "ipgTransactionId": "84681094268",
  "orderId": "R-2fa8eea7-fba5-4eff-8680-bcdb05766d25",
  "transactionType": "SALE",
  "paymentToken": {
     "reusable": true,
     "declineDuplicates": false,
     "brand": "MASTERCARD",
     "type": "NETWORK_TOKEN",
     "networkTokenProvisionStatus": "PROVISIONED"
  },
  "transactionOrigin": "ECOM",
  "paymentMethodDetails": {
     "paymentCard": {
        "expiryDate": {
           "month": "03",
           "year": "2028"
        },
        "fundingCardNumber": {
           "bin": "520424",
           "last4": "3013"
        },
        "bin": "520424",
        "last4": "7793",
        "brand": "MASTERCARD"
     },
     "paymentMethodType": "PAYMENT_CARD",
     "paymentMethodBrand": "MASTERCARD"
  },
  "terminalId": "98000002",
  "merchantId": "9900004",
  "transactionTime": 1743452556,
  "approvedAmount": {
     "total": 10.00,
     "currency": "ARS",
     "components": {
       "subtotal": 10.00
     }
   },
  "transactionAmount": {
     "total": 10.00,
     "currency": "ARS",
     "components": {
        "subtotal": 10.00
     }
  },
  "transactionStatus": "APPROVED",
  "approvalCode": "Y:370036:4681094268:PPXX:3700360179",
  "processor": {
     "referenceNumber": "370036370036",
     "authorizationCode": "370036",
     "responseCode": "00",
     "associationResponseCode": "XX",
     "responseMessage": "Function performed error-free",
     "avsResponse": {
        "streetMatch": "NO_INPUT_DATA",
        "postalCodeMatch": "NO_INPUT_DATA"
     },
     "securityCodeResponse": "NOT_CHECKED",
     "merchantAdviceCodeIndicator": "01",
     "taxRefundData": {}
  }
}
```


---

# Parte 5 — 3D Secure

Autenticación con proveedor propio (Frictionless, Challenge, Data Only), Passthrough, y códigos de respuesta.

## 10. 3D Secure

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §10*

Al utilizar nuestro Gateway y Fiserv como proveedor de 3-D Secure, la autenticación se realiza en línea con el flujo de transacciones existente. El proceso comienza realizando una autorización típica o una solicitud de venta con el deseo de realizar una autenticación 3-D Secure en la solicitud.

Luego, la autorización se coloca en un estado WAITING hasta que se complete el proceso de autenticación. Durante la autenticación, se le puede solicitar al comerciante que actualice la solicitud de transacción original una o más veces para avanzar en el flujo del proceso.

Al final del proceso de autenticación, la transacción original se actualiza con los resultados de la autenticación y se completa la autorización.

Los diagramas de secuencia a continuación corresponden a los pasos del texto que sigue. El primer diagrama es para el flujo sin fricción. Esto significa que el emisor no requiere que el titular de la tarjeta se autentique.

> **[Imagen/diagrama en el documento original]** — Diagrama de secuencia del flujo sin fricción (frictionless), en el que el emisor no requiere que el titular de la tarjeta se autentique.

El siguiente diagrama muestra el flujo cuando su cliente tiene que autenticarse, lo que significa que su emisor ha solicitado que proporcione detalles de autenticación adicionales.

> **[Imagen/diagrama en el documento original]** — Diagrama de secuencia del flujo con autenticación del cliente (challenge), cuando el emisor solicita detalles de autenticación adicionales.

Finalmente, en el siguiente flujo puede observarse cómo se lleva a cabo una transacción bajo el protocolo 3DS, de principio a fin.

> **[Imagen/diagrama en el documento original]** — Diagrama del flujo completo de una transacción bajo el protocolo 3DS, de principio a fin.

### 10.1 Implementación de 3DS (autenticación con proveedor propio)

#### 10.1.1 Paso 1: Iniciar un pago

Utilice la tarjeta de pago o el token de pago para iniciar una transacción de pago principal. Puede indicar al pago que utilice 3-D Secure si desea aplicarlo. Los RequestTypes relevantes para la autenticación 3-D Secure son los siguientes:

- PaymentCardPreAuthTransaction
- PaymentCardSaleTransaction
- PaymentTokenPreAuthTransaction
- PaymentTokenSaleTransaction
- PaymentCardPayerAuthTransaction

Este mensaje debe incluir el objeto authenticationRequest en el mensaje de solicitud de transacción e incluye los siguientes valores:

| Atributo | Descripción |
| --- | --- |
| authenticationType | El valor Secure3DAuthenticationRequest es un valor predeterminado para la solicitud de autenticación 3DS. |
| termURL | Indica la URL de devolución de llamada donde el servidor ACS debe publicar los resultados del proceso de autenticación (este es el servidor de control de acceso que ejecuta la autenticación del titular de la tarjeta). |
| methodNotifictionURL | Para recibir una notificación sobre la finalización de la visualización del formulario 3DSMethod, también debe enviar este elemento en su solicitud de transacción. La URL debe ser identificable de forma única, por lo que cuando se recibe una notificación en esta URL, debe poder asignarla a la transacción correspondiente. Esto elimina cualquier dependencia del Secure3dTransId que recibirá con la respuesta del formulario 3DSMethod. Una forma fácil de garantizar la asignación correcta de transacciones es pasar una referencia de transacción como una cadena de consulta. |
| challengeIndicator | En caso de que desee influir en qué flujo de autenticación debe usarse, puede enviar este elemento opcional con uno de los valores que se enumeran a continuación. En caso de que el Indicador de desafío no se envíe dentro de su solicitud de transacción, la puerta de enlace completará el valor predeterminado "01": sin preferencia. |
| challengeWindowSize | Si desea definir el tamaño de la ventana de desafío que se muestra a sus clientes durante el proceso de autenticación, puede enviar este elemento opcional con uno de los valores que se enumeran a continuación. |

Los valores disponibles para challengeIndicator son:

- 01 = Sin preferencia (No tiene preferencia sobre si se debe realizar un desafío. Este es el valor predeterminado)
- 02 = No se solicitó ningún desafío (Prefiere que no se realice ningún desafío).
- 03 = Desafío solicitado: Preferencia del Solicitante 3DS (Prefiere que se realice un desafío)
- 04 = Desafío solicitado: Mandato (Existen mandatos locales o regionales que significan que se debe realizar un desafío)
- 05 = No se solicitó desafío (Análisis de riesgo de transacción ya se realizó)
- 06 = No se solicitó desafío (Solo uso compartido de datos)
- 07 = No se solicitó desafío (SCA ya se realizó)
- 08 = No se solicitó desafío (utilice la exención de la lista blanca si no se requiere desafío)
- 09 = Desafío solicitado (solicitud de lista blanca solicitada si se requiere desafío)

Los valores disponibles para challengeWindowSize son:

- 01 = 250 x 400
- 02 = 390 x 400
- 03 = 500 x 600
- 04 = 600 x 400
- 05 = Full screen

El siguiente JSON representa un ejemplo de una solicitud de transacción de venta con un conjunto mínimo de elementos:

```json
{
  "requestType": "PaymentCardSaleTransaction",
  "transactionAmount": {
    "total": "122.04",
    "currency": "USD"
  },
  "paymentMethod": {
    "paymentCard": {
      "number": "403587XXXXXX4977",
      "securityCode": "977",
      "expiryDate": {
        "month": "12",
        "year": "24"
      }
    }
  },
  "authenticationRequest": {
    "authenticationType": "Secure3D21AuthenticationRequest",
    "termURL": "https://www.mywebshop.com/process3dSecure",
    "methodNotificationURL": "https://www.mywebshop.com/process3dSecureMethodNotification?transactionReferenceNumber=ffffffff-ba0b-539f-8000-016b2343ad7e",
    "challengeIndicator": "01",
    "challengeWindowSize": "01"
  }
}
```

No todos los emisores admiten la recopilación de datos del navegador mediante el formulario 3DSMethod. En esos casos, no se publicarán datos en methodNotificationURL, y el flujo debe continuar publicando un estado de EXPECTED_BUT_NOT_RECEIVED; consulte a continuación.

#### 10.1.2 Paso 2: Respuesta de autenticación segura

Utilice la tarjeta de pago o el token de pago para iniciar una transacción de pago principal. Nuestra respuesta incluirá un elemento 3DSMethod, que genera un iframe oculto que ayuda a recopilar los datos del navegador para los emisores. Esta información se suma al perfil general del consumidor y ayuda a identificar transacciones potencialmente fraudulentas. También aumenta la probabilidad de una transacción exitosa y sin fricciones.

Deberá incluir 3DSMethod en su sitio web como iframe oculto. No se presenta ninguna pantalla de interfaz de usuario al titular de la tarjeta.

En este punto, se realiza una solicitud de verificación para determinar si el sistema 3-D Secure funciona y si el titular de la tarjeta está inscrito en 3-D Secure. Si el sistema 3-D Secure no funciona o si el titular de la tarjeta no está inscrito, la transacción se procesará normalmente y será aprobada o rechazada por la red de procesamiento.

En el caso anterior, el estado de la transacción aparecerá así:

```
transactionStatus = APPROVED||DECLINED
```

Si se verifica que el titular de la tarjeta está inscrito en el programa 3-D Secure, se incluirá un objeto 'authenticationResponse' en la respuesta de la transacción.

Mientras espera la respuesta, la transacción tendrá el siguiente estado de transacción:

```
transactionStatus = WAITING
```

El objeto authenticationResponse contendrá los siguientes valores:

| Atributo | Valor |
| --- | --- |
| type | 3D_SECURE |
| version | 2.1 o 2.2 |
| secure3DMethod/methodForm | Datos de formulario HTML con iFrame oculto utilizado para recopilar los datos del navegador web para el Emisor. |
| secure3DMethod/secure3dTransId | Un identificador único para la transacción proporcionado por el servidor ACS del emisor. |

El siguiente documento JSON representa un ejemplo de una respuesta:

> **⚠ Advertencia sobre este payload.** El valor de `methodForm` es un formulario HTML completo embebido como string. En el PDF original viene partido en múltiples líneas y con espacios espurios dentro de las entidades HTML (`& lt;` en lugar de `&lt;`, `& amp;#10;` en lugar de `&amp;#10;`), producto de cómo el PDF renderiza el texto. **No copiar este bloque literalmente**: el `methodForm` real hay que tomarlo de la respuesta de la API. Se transcribe tal cual solo como referencia de estructura.

```json
{
  "clientRequestId": "30dd879c-ee2f-11db-8314-0800200c9a66",
  "apiTraceId": "rrt-0c80a3403e2c2def0-d-ea-28805-6810951-2",
  "ipgTransactionId": "838916029301",
  "transactionType": "SALE",
  "transactionTime": 1518811817,
  "approvedAmount": {
    "total": 122.04,
    "currency": "USD"
  },
  "transactionStatus": "WAITING",
  "authenticationResponse": {
    "type": "3D_SECURE",
    "version": "2.1",
    "secure3dMethod": {
      "methodForm": "&lt;!DOCTYPE iframe SYSTEM "about: legacy - compat"&gt;
             & lt;iframe id = "tdsMmethodTgtFrame" name = "tdsMmethodTgtFrame"
         style = "width: 1px; height: 1px; display: none;" src = "javascript:false;"
         xmlns = "http://www.w3.org/1999/xhtml" & gt;
    & lt; !--.--& gt; & lt; /iframe&gt;&lt;form id="tdsMmethodForm"
         name = "tdsMmethodForm"
         action = https://localhost.modirum.com:8543/dstests/ACSEmu2
         method = "post"
         target = "tdsMmethodTgtFrame" xmlns = "http://www.w3.org/1999/xhtml" & gt;
    & lt;input type = "hidden" name = "3DSMethodData"
         value =
"eyAidGhyZWVEU1NlcnZlclRyYW5zSUQiIDogIjAwMDAwMDAwLTU2NzYtNTY2My
       04MDAwLTAwMDAw & amp;#10;
MDAwNDFhOSIsICJ0aHJlZURTTWV0aG9kTm90aWZpY2F0aW9
       uVVJMIiA6ICJodHRwczovL2xvY2Fs & amp;#10;
aG9zdC5tb2RpcnVtLmNvbTo4NTQzL21kcGF5bXBpL
       01lcmNoYW50U2VydmVyP21uPVkmdHhpZD0x
         & amp;#10;
NjgwOSZkaWdlc3Q9aSUyQnhhUEF5NWFOcVJRbllqNmozbWFDZlFJbTdFdjJYTm
       kwNnh6YmZNJTJG & amp;#10;R3MlM0QiIH0"/&gt; &lt;input type="hidden"
       name = "threeDSMethodData"
       value =
"eyAidGhyZWVEU1NlcnZlclRyYW5zSUQiIDogIjAwMDAwMDAwLTU2NzYtNTY2
       My04MDAwLTAwMDA
       w & amp;#10;
MDAwNDFhOSIsICJ0aHJlZURTTWV0aG9kTm90aWZpY2F0aW9uVVJMIiA
       6ICJodHRwczovL2xvY 2Fs & amp;#10;
aG9zdC5tb2RpcnVtLmNvbTo4NTQzL21kcGF5bXBpL01lcm
       NoYW50U2VydmVyP21uPVkmdHhpZD0x & amp;#10;
NjgwOSZkaWdlc3Q9aSUyQnhhUEF5NWFOcV
       JRbllqNmozbWFDZlFJbTdFdjJYTmkwNnh6YmZNJTJG &
amp;#10;R3MlM0QiIH0"/&gt;
         & lt; /form&gt;&lt;script type="text/javascript"
       xmlns = "http://www.w3.org/1999/xhtml" & gt;
       document.getElementById("tdsMmethodForm").submit(); & lt; /script&gt;",
      "secure3dTransId": "3ac7caa7-aa42-2663-791b-2ac05a542c4a"
    }
  }
}
```

#### 10.1.3 Paso 3: 3DSMethod Solicitud de notificación y respuesta

El 'methodForm' de 3-D Secure se utiliza para proporcionar detalles del entorno del titular de la tarjeta al servidor de control de acceso del emisor (ACS). El methodForm contiene el HTML para un iFrame oculto que se incluirá en su página web. Esto obligará a que la información se publique automáticamente en el servidor ACS a través de Fiserv. La información HTML es un bloque HTML autónomo que no necesita modificarse ni publicarse, ya que se cuidará automáticamente cuando se represente la página en la que se inserta. Alternativamente, esto se puede crear en una página que nunca sea visible para el titular de la tarjeta.

Si se reciben correctamente, los datos de respuesta se publicarán en la URL proporcionada en el campo methodNotificationURL original y el mensaje publicado contendrá un campo threeDSServerTransID que contiene el ID de transacción ACS único asociado con el original solicitud. Tenga en cuenta que la carga útil para esta respuesta contendrá un solo elemento llamado tresDSMethodData. Ese elemento contendrá una respuesta JSON codificada en base64 que contiene el campo threeDSServerTransID.

Ejemplo:

```html
<form name="frm" method="POST" action="{value from methodNotificationURL}">
  <input type="hidden" name="threeDSMethodData"
value="eyJ0aHJlZURTU2VydmVyVHJhbnNJRCI6IjNhYzdjYWE3LWFhNDItMjY2My03OTFiLTJhYzA1YTU0MmM0YSJ9">
</form>
```

Descifrado threeDSMethodData:

```json
{"threeDSServerTransID":"3ac7caa7-aa42-2663-791b-2ac05a542c4a"}
```

El threeDSServerTransID no es necesario para ningún otro procesamiento de 3DS. Sin embargo, se recomienda guardar este valor como referencia para el servidor 3DS en el futuro si es necesario.

Debe esperar un mínimo de 10 segundos para que se complete la operación POST anterior y luego determinar el estado de notificación del método de la siguiente manera:

| Estatus | Descripción |
| --- | --- |
| RECEIVED | Ha enviado el elemento methodNotificationURL en la solicitud de transacción de Venta inicial y ha recibido la notificación de ACS en 10 segundos, recibirá un mensaje HTTP POST de ACS, que contendrá un identificador de transacción único representado por secure3dTransId. |
| EXPECTED_BUT_NOT_RECEIVED | Ha enviado el elemento methodNotificationURL en la solicitud de transacción de Venta inicial y no ha recibido la notificación de ACS en 10 segundos. |
| NOT_EXPECTED | NO ha enviado el elemento methodNotificationURL en la solicitud de transacción de venta inicial. |

\* Puede haber ocasiones en las que observará respuestas duplicadas a su 'URL de notificación de 3DSMethod' o 'URL de término', esto podría deberse a solicitudes duplicadas enviadas desde el ACS de un emisor o quizás al comportamiento del usuario dentro del navegador. Se recomienda que incorpore el manejo en su sistema, de modo que, en caso de que reciba una respuesta duplicada a su 'URL de notificación de 3DSMethod' o 'URL de término', no envíe una solicitud adicional/duplicada a la puerta de enlace.

#### 10.1.4 Alternativa A: Flujo Frictionless

##### a. Solicitud para continuar con la autenticación 3DS:

Una vez que se haya completado la llamada al Método 3DS, debe notificar a la puerta de enlace que el proceso de autenticación puede continuar enviando el elemento 'methodNotificationStatus' con los valores basados en las condiciones correspondientes del formulario 3DSMethod anterior. Esto se hace realizando una operación PATCH en la transacción original.

También puede incluir la dirección de facturación del titular de la tarjeta opcional y el código de seguridad en este momento.

El siguiente documento JSON representa un ejemplo de una solicitud que se enviará después de mostrar el formulario 3DSMethod:

```json
{
  "authenticationType": "Secure3D21AuthenticationUpdateRequest",
  "storeId": "12345500000",
  "billingAddress": {
    "company": "Test Company",
    "address1": "5565 Glenridge Conn",
    "address2": "Suite 123",
    "city": "Atlanta",
    "region": "Georgia",
    "postalCode": "30342",
    "country": "USA"
  },
  "securityCode": "123",
  "methodNotificationStatus": "RECEIVED"
}
```

##### b. Respuesta final de 3DS:

Cuando se determina que se ha realizado un flujo sin fricciones (es decir, el cliente ha sido completamente autenticado por su banco sin necesidad de interacción directa), se completa el proceso de 3-D Secure y se procesa la autorización de la transacción.

La respuesta de la transacción contiene un objeto secure3dResponse y la transacción se aprueba o se rechaza.

```
transactionStatus = APPROVED or DECLINED
```

El objeto 'secure3dResponse' contendrá el siguiente campo: 'responseCode3dSecure'.

El siguiente documento JSON representa un ejemplo de una respuesta que recibe de la API que indica que la autorización se ha realizado correctamente:

```json
{
  "clientRequestId": "30dd879c-ee2f-11db-8314-0800200c9a66",
  "apiTraceId": "rrt-0c80a3403e2c2def0-d-ea-28805-6810951-2",
  "ipgTransactionId": "838916029301",
  "transactionType": "SALE",
  "transactionTime": 1518811817,
  "approvedAmount": {
    "total": 122.04,
    "currency": "USD"
  },
  "transactionStatus": "APPROVED",
  "schemeTransactionId": "019078743804756",
  "processor": {
    "responseCode": "00",
    "responseMessage": "APPROVED",
    "authorizationCode": "OK7118"
  },
  "secure3dResponse": {
    "responseCode3dSecure": "1"
  }
}
```

#### 10.1.5 Alternativa B: Flujo Challenge

El flujo de desafío se activa cuando la transacción no se considera de bajo riesgo o cuando el Emisor requiere una autenticación adicional por parte del titular de la tarjeta. Todo el proceso comienza con una solicitud inicial de transacción de Autorización o Venta a través del paso donde se muestra 3DSMethod, como se describe en los Pasos 1 a 4 anteriores.

##### a. Solicitud para continuar con la autenticación 3DS:

Una vez que se haya completado la llamada al método 3DS, debe notificar a la puerta de enlace que el proceso de autenticación puede continuar enviando el elemento 'methodNotificationStatus' con los valores basados en las condiciones correspondientes del formulario del método 3DS anterior. Esto se hace realizando una operación PATCH en la transacción original.

También puede incluir la dirección de facturación del titular de la tarjeta opcional y el código de seguridad en este momento.

El siguiente documento JSON representa un ejemplo de una solicitud que se enviará después de la visualización del formulario 3DSMethod:

```json
{
  "authenticationType": "Secure3D21AuthenticationUpdateRequest",
  "storeId": "12345500000",
  "methodNotificationStatus": "RECEIVED"
}
```

##### b. Gateway responde para continuar con la autenticación 3DS:

Para el flujo de desafío, el estado de la transacción se devolverá de la siguiente manera:

```
transactionStatus = "WAITING"
```

La respuesta contendrá un objeto authenticationResponse con los siguientes campos:

| Campo | Descripción |
| --- | --- |
| type | 3D_SECURE |
| version | 2.1 o 2.2 |
| acsURL | La URL en la que se deben publicar los valores 'cReq' y 'session Data' para que se lleve a cabo el desafío del titular de la tarjeta. |
| termURL | La URL donde se publicarán los resultados de la autenticación. |
| cReq | Un mensaje de solicitud de desafío codificado devuelto desde el servidor ACS. |
| sessionData | Una lista codificada de parámetros de sesión que se utilizará para la autenticación. Tenga en cuenta que es posible que no siempre se proporcione este valor. |

El siguiente documento JSON representa un ejemplo de una respuesta:

```json
{
  "clientRequestId": "30dd879c-ee2f-11db-8314-0800200c9a66",
  "apiTraceId": "rrt-0c80a3403e2c2def0-d-ea-28805-6810951-2",
  "ipgTransactionId": "838916029301",
  "transactionType": "SALE",
  "transactionTime": 1518811817,
  "approvedAmount": {
    "total": 122.04,
    "currency": "USD"
  },
  "transactionStatus": "WAITING",
  "authenticationResponse": {
    "type": "3D_SECURE",
    "version": "2.1",
    "params": {
      "acsURL": "https://3ds-acs.test.modirum.com/mdpayacs/pareq",
      "termURL": "https://www.mywebshop.com/process3dSecure/",
      "cReq": "ewogICAiYWNzVHJhbCIgOiA...wMDAtMDAwMDAwMDA0MWE5Igp9",
      "sessiondata": "50F2156E03083CA665BCB4.."
    }
  }
}
```

##### c. Challenge del titular de la tarjeta:

En el siguiente paso, debe enviar los datos al acsURL indicado, que generalmente se implementa como un formulario de envío automático. Esto debe implementarse en su sitio web. El titular de la tarjeta será redirigido al ACS y se le presentará la interfaz de usuario para recopilar los detalles de autenticación, por ejemplo, ingresar una contraseña de un solo uso o realizar la autenticación utilizando su aplicación bancaria. Una vez completada la autenticación, se redirige al consumidor a su página web.

Debe publicar los valores cReq y sessionData en la URL especificada en el campo acsURL. Esta información se publica utilizando los siguientes nombres de campo:

| Campo | Descripción |
| --- | --- |
| cReq | Todo el mensaje cReq codificado en base64 como se obtuvo anteriormente. |
| threeDSSessionData | Todo el mensaje sessionData codificado en base64 como se obtuvo anteriormente. |

Ejemplo:

```html
<form name="frm" method="POST" action="https://3ds-acs.test.modirum.com/mdpayacs/pareq ">
 <input type=”hidden” name=”creq”
value=”ewogICAiYWNzVHJhbCIgOiA...wMDAtMDAwMDAwMDA0MWE5Igp9”>
 <input type=”hidden” name=”threeDSSessionData”
value=”50F2156E03083CA665BCB4..”>
</form>
```

Cuando se complete la autenticación, se publicará una respuesta de autenticación en la URL especificada en el campo 'termURL'.

##### d. Solicitud para completar la transacción

Después de recibir los datos del ACS, debe enviarlos al Gateway en el elemento cRes junto con la referencia a la transacción original. Esto se hace enviando una solicitud PATCH a la transacción original e incluye los siguientes valores:

| Campo | Valor / Descripción |
| --- | --- |
| authenticationType | Secure3D21AuthenticationUpdateRequest |
| acsResponse/cRes | Los datos cRes publicados en termURL por el servidor ACS. |

Se recomienda incluir la dirección de facturación opcional del titular de la tarjeta y el código de seguridad en este momento.

El siguiente documento JSON representa un ejemplo de una solicitud con el elemento 'cRes':

```json
{
  "authenticationType": "Secure3D21AuthenticationUpdateRequest",
  "storeId": "12345500000",
  "billingAddress": {
    "company": "Test Company",
    "address1": "5565 Glenridge Conn",
    "address2": "Suite 123"
    "city": "Atlanta",
    "region": "Georgia",
    "postalCode": "30342",
    "country": "USA"
  },
  "securityCode": "123",
  "acsResponse": {
    "cRes": "ewogICAiYWNzUmVmZX…Fuc1N0YXR…IKfQ=="
  }
}
```

##### e. Última respuesta

Dado que esta transacción se inició como una 'Sale', la autorización se realiza como parte de este paso final, si la autenticación fue exitosa.

La respuesta de la transacción contiene un objeto secure3dResponse y la transacción se aprueba o rechaza.

El objeto secure3dResponse contendrá el siguiente campo: responseCode3dSecure

El siguiente documento JSON representa un ejemplo de una respuesta que recibe que indica que la autorización se ha realizado correctamente:

```json
{
  "clientRequestId": "30dd879c-ee2f-11db-8314-0800200c9a66",
  "apiTraceId": "rrt-0c80a3403e2c2def0-d-ea-28805-6810951-2",
  "ipgTransactionId": "838916029301",
  "transactionType": "SALE",
  "transactionTime": 1518811817,
  "approvedAmount": {
    "total": 122.04,
    "currency": "USD"
  },
  "transactionStatus": "APPROVED",
  "schemeTransactionId": "019078743804756",
  "processor": {
    "responseCode": "00",
    "responseMessage": "APPROVED",
    "authorizationCode": "OK7118"
  },
  "secure3dResponse": {
    "responseCode3dSecure": "1"
  }
}
```

```http
PATCH /ipgrestapi/v2/services/payments/{ipgTransactionId}
```

```json
{
  "authenticationType": "Secure3D10AuthenticationUpdateRequest",
  "billingAddress": {
    "address1": "5565 Glenridge Conn",
    "city": "Atlanta",
    "postalCode": 30342,
    "country": "USA"
  },
  "merchantData": "MD____13992017033012241629.....c-4a40-aeb4-b41a8a34480fa067ac",
  "payerAuthenticationResponse": "eJzlWFeP67iS/………9Xm88X5c/37Pcj6I/v3P8JV86aGw=="
}
```

El siguiente documento JSON representa un ejemplo de una respuesta que recibe del Gateway que indica que la autorización se realizó correctamente y se marcó como autenticada:

```json
{
  "clientRequestId": "4c3aa885-db8e-43fb-b3c4-0e5c6927408c",
  "apiTraceId": "YKUjRJVBbdinNESL8Era8AAAAIs",
  "ipgTransactionId": "84563547902",
  "orderId": "R-ff489e2d-b5f3-4757-a91b-0a774681e26a",
  "transactionType": "SALE",
  "transactionOrigin": "ECOM",
  "paymentMethodDetails": {
    "paymentCard": {
      "expiryDate": {
        "month": "12",
        "year": "2024"
      },
      "bin": "403587",
      "last4": "4977",
      "brand": "VISA"
    },
    "paymentMethodType": "PAYMENT_CARD"
  },
  "country": "Germany",
  "terminalId": "80000860",
  "merchantId": "000102072004393",
  "transactionTime": 1621434858,
  "approvedAmount": {
    "total": 12.99,
    "currency": "EUR",
    "components": { "subtotal": 12.99 }
  },
  "transactionStatus": "APPROVED",
  "secure3dResponse": { "responseCode3dSecure": "1" },
  "schemeTransactionId": "519154004377788",
  "processor": {
    "referenceNumber": "113914232351",
    "authorizationCode": "907587",
    "responseCode": "00",
    "responseMessage": "Function performed error-free",
    "avsResponse": {
      "streetMatch": "N",
      "postalCodeMatch": "N"
    }
  }
}
```

#### 10.1.6 Data Only (solo Mastercard)

El siguiente es un ejemplo de una transacción bajo la modalidad 3DS Data Only. Esta modalidad está disponible únicamente para Mastercard.

Debe agregarse dentro de la sección authenticationRequest el parámetro adicional messageCategory con el valor 80.

Request:

```json
{
   "transactionAmount": {
      "total": "110.00",
      "currency": "ARS"
   },
   "requestType": "PaymentCardSaleTransaction",
   "storeId": "5919122412",
   "authenticationRequest": {
      "authenticationType": "Secure3DAuthenticationRequest",
      "termURL": "https://www.mywebshop.com/process3dSecure",
      "methodNotificationURL": "https://www.mywebshop.com/process3dSecureMethodNotification?transactionReferenceNumber=ffffffff-ba0b-539f-8000-016b2343ad7e",
      "messageCategory": "80"
   },
   "paymentMethod": {
      "paymentCard": {
         "number": "5165850000000008",
         "securityCode": "123",
         "expiryDate": {
            "month": "12",
            "year": "29"
         }
      },
      "paymentFacilitator": {
         "paymentFacilitatorId": "1212",
         "externalMerchantId": "123456",
         "name": "PFAC A",
         "subMerchantData": {
            "mcc": "5969",
            "legalName": "Fiserv",
            "merchantId": "12345",
            "address": {
               "address1": "Ingeniero M 456",
               "city": "Buenos Aires",
               "postalCode": "1234",
               "country": "ARG"
            },
            "document": {
               "type": "NATIONAL_IDENTITY",
               "number": 12345678910
            }
         }
      }
   },
   "order": {
      "orderId": "309",
      "installmentOptions": {
         "numberOfInstallments": 1
      }
   }
}
```

> **⚠ El ejemplo de respuesta de esta sección es inconsistente en el PDF original.** El request usa una Mastercard (`5165850000000008`, `storeId 5919122412`, total `110.00`), pero la respuesta que lo acompaña devuelve `"brand": "VISA"`, `"bin": "414746"`, `"country": "Singapore"` y un importe de `5.00`. Como Data Only es exclusivo de Mastercard, la respuesta parece copiada de otro ejemplo. Lo único que hay que leer de ahí es la forma del campo `secure3dResponse.responseCode3dSecure`. La respuesta correcta para Data Only sobre Mastercard está en §10.2.2.

Response:

```json
{
  "clientRequestId": "33e26aff-b16b-4271-98f3-e35761c98f13",
  "apiTraceId": "ZV35uOrD-zje5JZ3gFYVzgAAAdU",
  "ipgTransactionId": "84642140429",
  "orderId": "R-5a605c11-f889-4ef6-b366-9222f0127f44",
  "transactionType": "SALE",
  "paymentToken": {
     "reusable": true,
     "declineDuplicates": false,
     "brand": "VISA",
     "type": "PAYMENT_CARD"
  },
  "transactionOrigin": "ECOM",
  "paymentMethodDetails": {
     "paymentCard": {
        "expiryDate": {
           "month": "12",
           "year": "2029"
        },
        "bin": "414746",
        "last4": "0083",
        "brand": "VISA"
     },
     "paymentMethodType": "PAYMENT_CARD",
     "paymentMethodBrand": "VISA"
  },
  "country": "Singapore",
  "terminalId": "98001001",
  "merchantId": "9900004",
  "transactionTime": 1700657603,
  "approvedAmount": {
     "total": 5.00,
     "currency": "ARS",
     "components": {
        "subtotal": 5.00
     }
  },
  "transactionAmount": {
     "total": 5.00,
     "currency": "ARS",
     "components": {
        "subtotal": 5.00
     }
  },
  "transactionStatus": "APPROVED",
  "approvalCode": "Y:051444:4642140429:PPXX:0514440332",
  "secure3dResponse": {
     "responseCode3dSecure": "A"
  },
  "processor": {
     "referenceNumber": "051444051444",
     "authorizationCode": "051444",
     "responseCode": "00",
     "responseMessage": "Function performed error-free",
     "avsResponse": {
        "streetMatch": "NO_INPUT_DATA",
        "postalCodeMatch": "NO_INPUT_DATA"
     },
     "securityCodeResponse": "NOT_CHECKED"
  }
}
```

### 10.2 Implementación de 3DS Passthrough (autenticación con proveedor externo)

En caso de que esté utilizando su propio proveedor de servicios 3DS o externo y planee enviar una solicitud de autorización al Gateway, debe enviar los valores de autenticación obtenidos de su proveedor de servicios 3DS.

| Field | Descripción |
| --- | --- |
| authenticationType | Used for submitting authentication result performed by an external 3-D Secure service provider |
| cavv | Authentication value obtained in the authentication response from external 3-D Secure service provider |
| dsTransactionId | Authentication transaction reference ID, obtained from external 3-D Secure provider |
| authenticationResponse | Represents the result of the authentication, allowed values are : Y = fully authenticated transaction, A = Successful Authentication Attempt, U = Unable to Authenticate by DS or ACS |

#### 10.2.1 3DS Full Authentication Passthrough

El siguiente documento JSON representa un ejemplo de una transacción de venta enviada a nuestro Gateway después de haber sido completamente autenticada por un proveedor de servicios externo:

```json
{
  "requestType": "PaymentCardSaleTransaction",
  "transactionAmount": {
    "total": "12.00",
    "currency": "EUR"
  },
  "paymentMethod": {
    "paymentCard": {
      "number": "401699XXXX0006",
      "securityCode": "999",
      "expiryDate": {
        "month": "12",
        "year": "24"
      }
    }
  },
  "authenticationResult": {
    "authenticationType": "Secure3DAuthenticationResult",
    "cavv": "AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "dsTransactionId": "5a56fdc9-6d47-5fee-8000-000000296743",
    "authenticationResponse": "Y"
  }
}
```

El siguiente documento JSON representa un ejemplo de una respuesta que recibe del Gateway que indica que la autorización se realizó correctamente y se marcó como totalmente autenticada:

```json
{
  "clientRequestId": "97c67e8f-7c2d-421d-9d97-b749206aab06",
  "apiTraceId": "YJPLezoO2XZa9K8QL10bvgAAA98",
  "ipgTransactionId": "84411977859",
  "orderId": "R-941fc643-adae-4468-bc48-26e5099f4367",
  "transactionType": "SALE",
  "transactionOrigin": "ECOM",
  "paymentMethodDetails": {
    "paymentCard": {
      "expiryDate": {
        "month": "12",
        "year": "2024"
      },
      "bin": "401699",
      "last4": "0006",
      "brand": "VISA"
    },
    "paymentMethodType": "PAYMENT_CARD"
  },
  "country": "USA",
  "terminalId": "80000012",
  "merchantId": "520334507229862",
  "transactionTime": 1620298619,
  "approvedAmount": {
    "total": 12,
    "currency": "EUR",
    "components": { "subtotal": 12 }
  },
  "transactionStatus": "APPROVED",
  "secure3dResponse": { "responseCode3dSecure": "1" },
  "schemeTransactionId": "234567891234560",
  "processor": {
    "referenceNumber": "112610940537",
    "authorizationCode": "005042",
    "responseCode": "00",
    "responseMessage": "Function performed error-free",
    "avsResponse": {
      "streetMatch": "Y",
      "postalCodeMatch": "Y"
    },
    "securityCodeResponse": "MATCHED"
  }
}
```

#### 10.2.2 3DS Data Only Passthrough

El siguiente es un ejemplo de una transacción bajo la modalidad 3DS Data Only cuando la autenticación se obtuvo con un proveedor externo. Esta modalidad está disponible únicamente para Mastercard.

Debe agregarse dentro de la sección authenticationResult los siguientes parámetros:

| Campo | Descripción o Valor |
| --- | --- |
| authenticationType | Secure3DAuthenticationResult |
| authenticationResponse | U |
| cavv | Criptograma recibido en el momento de la autenticación bajo la modalidad Data Only. Ejemplo de criptograma: AAABCZIhcQAAAABZlyFxAAAAAAA |
| dsTransactionId | Código de identificación de la transacción según el Directory Server. |
| transactionStatus | Y |
| messageCategory | 80 |

Request:

```json
{
  "transactionAmount": {
     "total": "5.00",
     "currency": "ARS"
  },
  "requestType": "PaymentCardSaleTransaction",
  "storeId": "59123456789",
  "paymentMethod": {
     "paymentCard": {
        "number": "5165850000000008",
        "securityCode": "123",
        "expiryDate": {
           "month": "12",
           "year": "29"
        }
     }
  },
  "authenticationResult": {
     "authenticationType": "Secure3DAuthenticationResult",
     "authenticationResponse": "U",
     "cavv": "AAABCZIhcQAAAABZlyFxAAAAAAA",
     "dsTransactionId": "f38e6948-5388-41a6-bca4-b49723c19437",
     "transactionStatus": "Y",
     "messageCategory": "80"
  }
}
```

Response:

```json
{
  "clientRequestId": "dbc7d4d3-ba03-4037-866b-8c02c0da7414",
  "apiTraceId": "ZV39N6L5gf7KjOoFlakkFQAAAzw",
  "ipgTransactionId": "84642141445",
  "orderId": "R-8596ac10-8087-4931-9eaa-ec0e24ae84d8",
  "transactionType": "SALE",
  "paymentToken": {
     "reusable": true,
     "declineDuplicates": false,
     "brand": "MASTERCARD",
     "type": "PAYMENT_CARD"
  },
  "transactionOrigin": "ECOM",
  "paymentMethodDetails": {
     "paymentCard": {
        "expiryDate": {
           "month": "12",
           "year": "2029"
        },
        "bin": "516585",
        "last4": "0008",
        "brand": "MASTERCARD"
     },
     "paymentMethodType": "PAYMENT_CARD",
     "paymentMethodBrand": "MASTERCARD"
  },
  "country": "Argentina",
  "terminalId": "98001001",
  "merchantId": "9900004",
  "transactionTime": 1700658487,
  "approvedAmount": {
     "total": 5.00,
     "currency": "ARS",
     "components": {
        "subtotal": 5.00
     }
  },
  "transactionAmount": {
     "total": 5.00,
     "currency": "ARS",
     "components": {
        "subtotal": 5.00
     }
  },
  "transactionStatus": "APPROVED",
  "approvalCode": "Y:052256:4642141445:PPXX:0522560333",
  "secure3dResponse": {
     "responseCode3dSecure": "A"
  },
  "processor": {
     "referenceNumber": "052256052256",
     "authorizationCode": "052256",
     "responseCode": "00",
     "responseMessage": "Function performed error-free",
     "avsResponse": {
        "streetMatch": "NO_INPUT_DATA",
        "postalCodeMatch": "NO_INPUT_DATA"
     },
     "securityCodeResponse": "NOT_CHECKED"
  }
}
```

### 10.3 Códigos de respuesta de autenticación y condiciones para el paso a la autorización

A continuación, se muestra un listado con los códigos de respuesta posibles respecto a la autenticación, sus respectivos casos de uso, sus valores ECI y la indicación sobre si son elegibles para pasar al host de autorización:

| Código de respuesta 3dsecure | Caso de Uso | Valor ECI | Proceso de Autorización |
| --- | --- | --- | --- |
| 1 | Transacción completamente autenticada (con CAVV/AAV) | ECI2/ECI5 | Mensaje de autorización enviado al procesador |
| 3 | Autenticación fallida (rechazada por DS o ACS) | ECI7 | La solicitud de autorización es declinada por el gateway con respuesta “N:-50716:3D Secure authentication failed” |
| 4 | Intento de autenticación (successful attempt). El tarjetahabiente no se pudo autenticar en el portal del emisor | ECI1/ECI6 | Se envía autorización al procesador; El comercio puede decidir bloquear las transacciones con ECI 1 y ECI 6ª nivel tienda |
| 5 | No es posible autenticar debido a un error del DS – usado para versión 1 del protocolo 3DS | ECI7 | Se envía autorización al procesador; el comercio puede decidir bloquear todas las transacciones con ECI 7 a nivel tienda |
| 6 | No se puede autenticar (la se puede autenticar con el ACS o DS) | ECI7 | Se envía autorización al procesador; el comercio puede decidir bloquear todas las transacciones con ECI 7 a nivel tienda |
| 7 | Falló la autenticación (la tarjeta no está registrada en el DS) – utilizado en la V1 del protocolo 3DS | ECI7 | Se envía autorización al procesador; el comercio puede decidir bloquear todas las transacciones con ECI 7 a nivel tienda |
| 8 | Valores o combinación de elementos de autenticación no válidos | N/A | La transacción es declinada por el gateway con respuesta N:-5100:Invalid 3D Secure values (relevante para protocolo 3DS V1) |
| A | Transacción Mastercard Insights / Data Only exitosa | ECI7 | Se envía autorización al procesador; el comercio puede decidir bloquear todas las transacciones con ECI 7 a nivel tienda |
| B | Transacción Mastercard Insights / Data Only no exitosa | ECI7 | Se envía autorización al procesador; el comercio puede decidir bloquear todas las transacciones con ECI 7 a nivel tienda |

Bloque original tal como aparece en el PDF (para referencia de layout):

```
  Código de
  respuesta            Caso de Uso                 Valor ECI            Proceso de Autorización
  3dsecure

                 Transacción
                 completamente                                 Mensaje de autorización enviado al
      1                                            ECI2/ECI5
                 autenticada (con                              procesador
                 CAVV/AAV)

                 Autenticación fallida                         La solicitud de autorización es declinada por
      3          (rechazada por DS o                  ECI7     el gateway con respuesta “N:-50716:3D
                 ACS)                                          Secure authentication failed”

                 Intento de autenticación
                                                               Se envía autorización al procesador; El
                 (successful attempt). El
                                                               comercio puede decidir bloquear las
      4          tarjetahabiente no se             ECI1/ECI6
                                                               transacciones con ECI 1 y ECI 6ª nivel
                 pudo autenticar en el
                                                               tienda
                 portal del emisor

                 No es posible autenticar
                                                               Se envía autorización al procesador; el
                 debido a un error del DS
      5                                               ECI7     comercio puede decidir bloquear todas las
                 – usado para versión 1
                                                               transacciones con ECI 7 a nivel tienda
                 del protocolo 3DS

                 No se puede autenticar                        Se envía autorización al procesador; el
      6          (la se puede autenticar              ECI7     comercio puede decidir bloquear todas las
                 con el ACS o DS)                              transacciones con ECI 7 a nivel tienda

                 Falló la autenticación (la
                                                               Se envía autorización al procesador; el
                 tarjeta no está registrada
      7                                               ECI7     comercio puede decidir bloquear todas las
                 en el DS) – utilizado en la
                                                               transacciones con ECI 7 a nivel tienda
                 V1 del protocolo 3DS

                 Valores o combinación                         La transacción es declinada por el gateway
      8          de elementos de                       N/A     con respuesta N:-5100:Invalid 3D Secure
                 autenticación no válidos                      values (relevante para protocolo 3DS V1)

                 Transacción Mastercard                        Se envía autorización al procesador; el
      A          Insights / Data Only                 ECI7     comercio puede decidir bloquear todas las
                 exitosa                                       transacciones con ECI 7 a nivel tienda

                 Transacción Mastercard                        Se envía autorización al procesador; el
      B          Insights / Data Only no              ECI7     comercio puede decidir bloquear todas las
                 exitosa                                       transacciones con ECI 7 a nivel tienda
```

### 10.4 Campos mandatorios y opcionales de una transacción autenticada con 3DS

**Transacciones de autenticación**

| | |
| --- | --- |
| requestType posibles (siempre mandatorio) | PaymentCardSaleTransaction<br>PaymentCardPreAuthTransaction |
| Campos mandatorios adicionales para 3DS | authenticationRequest/athenticationType<br>authenticationRequest/athenticationType/termURL<br>authenticationRequest/athenticationType/methodNotificationURL<br>Parámetros mandatorios de la transacción primaria elegida \* |
| Campos opcionales adicionales para 3DS | authenticationRequest/athenticationType/messageCategory \*\*<br>authenticationRequest/athenticationType/challengeWindowSize<br>authenticationRequest/athenticationType/browserJavaScriptEnabled<br>authenticationRequest/athenticationType/browserJavaEnabled<br>authenticationRequest/athenticationType/authenticationIndicator |
| Campos sugeridos adicionales para 3DS | paymentMethod/paymentCard/ cardholderName<br>Order/Billing/ name<br>Order/Billing/Contact/ Phone<br>Order/Billing/Contact/ MobilePhone<br>Order/Billing/Contact/ Email<br>Order/Billing/Address/ Address1<br>Order/Billing/Address/ City<br>Order/Billing/Address/PostalCode<br>Order/Billing/Address/ Country<br>Order/Shipping/Address/ Address1<br>Order/Shipping/Address/ City<br>Order/Shipping/Address/postalCode |

\* Deben adicionarse al resto de los campos mandatorios de la transacción elegida (PaymentCardSaleTransaction o PaymentCardPreAuthTransaction).

\*\* El campo messageCategory es mandatorio para la modalidad 3DS Data Only, en cuyo caso debe enviarse con el valor 80. Dicho servicio está solo disponible para Mastercard.

### 10.5 Ejemplo de transacción autenticada con 3DS

```json
{
  "transactionAmount": {
     "total": "1.00",
     "currency": "ARS"
  },
  "requestType": "PaymentCardSaleTransaction",
  "paymentMethod": {
     "paymentCard": {
        "number": "5579220000000012",
        "securityCode": "123",
        "expiryDate": {
          "month": "12",
          "year": "22"
        }
     }
  },
  "authenticationRequest": {
     "authenticationType": "Secure3D21AuthenticationRequest",
     "termURL": "http://localhost/3DS/finalize.php",
     "methodNotificationURL": "https://micomercio.com/logs/notification.php",
     "challengeIndicator": "03"
  }
}
```

El payload del ejemplo anterior pertenece a una transacción de venta autenticada con 3DS. La respuesta obtenida por parte de IPG deberá ser similar a la siguiente:

> **⚠ Advertencia sobre este payload.** Los valores de `payerAuthenticationRequest` y `merchantData` venían partidos en varias líneas en el PDF original; acá se unieron en una sola cadena. Aun así conservan artefactos del PDF (un espacio dentro del base64 de `payerAuthenticationRequest`, y espacios alrededor de los guiones en el UUID final de `merchantData`). **No copiarlos literalmente**: son valores de ejemplo y los reales vienen en la respuesta de la API.

```json
{
  "clientRequestId": "91e98916-c5f0-4520-93b3-d520e635fc30",
  "apiTraceId": "rrt-0657cd7557d7d3602-b-ea-21046-17325498-1",
  "ipgTransactionId": "84531462889",
  "orderId": "R-6fd2afaf-d16a-40bd-a579-80be51f840a9",
  "transactionType": "SALE",
  "transactionOrigin": "ECOM",
  "paymentMethodDetails": {
     "paymentCard": {
        "expiryDate": {
           "month": "12",
           "year": "2022"
        },
        "bin": "557922",
        "last4": "0012",
        "brand": "MASTERCARD"
     },
     "paymentMethodType": "PAYMENT_CARD"
  },
  "country": "Argentina",
  "transactionTime": 1583257456,
  "authenticationResponse": {
     "type": "3D_SECURE",
     "version": "1.0",
     "params": {
       "payerAuthenticationRequest": "eJxVUttuwjAM/ZWK9zZJKVCQiQRD00ACFZimaW8hdaGMpqWXwfb1S0o7mF/ic+w49nHg9ZAjzrYoqxw5LLEoxB6tOBx3gs16Y/ej0BWRiOyQ9YXt0V1oi95gaPt0hz0W+R4Vww6HYLLBM4cvzIs4VZw51HGBtFCXzeVBqJKDkOfpfMV7tQFpICSYz2ec3Q3IjQIlEuSrWH5a64m1lWkZiyDdAql5kGmlyvybe74HpAVQ5Sd+KMusGBFyuVycTOzTIlWnWKGTXIGYOJB7U0FlvELXu8YhRxI8V9GyeCeLadL1s2PZPb8tPuKf43IMxGRAKErkLnUp7dKuxQYjzxuxPpCaB5GYRjijVA948yEzT0weAo8EaPFzVLKdo0WA1yxVqDO0mH8+hFhI3X9z3Jt/ejH6ylLL5ruM+gOfGYVrwpSKtTauy261DABirpB meaRZvvb+fYpfztmzWQ==",
       "termURL": "http://localhost/3DS/finalize.php",
       "merchantData": "MD___________100202003031744162484e/PFufMsX/JBm38pjt3qVJZizjM=_____555555_____________11111111111______R-6fd2afaf-d16a-40bda5790ww_________________________________________________________________________________________returnurl ?_______________________________________________________________________________________VRQR - 6fd2afaf - d16a - 40bd - a579 - 80be51f840a999e3af",
       "acsURL": "https://3ds-acs.test.modirum.com/mdpayacs/pareq"
     }
  }
}
```

## Comunicación a comercios — 3D Secure

*Fuente: Comunicacion comercios 3DS.pdf*

Protocolo 3D-Secure

Agregá una capa adicional de seguridad a las ventas online

El comercio online está en pleno auge en la región, lo que hace indispensable contar con medidas de seguridad. En respuesta a ello, Mastercard exige que los comercios implementen 3DS en las ventas que realicen con su marca. Para Visa es opcional.

> **[Imagen/diagrama en el documento original]** — ilustración extraída del documento "Data-Only-Infographic.pdf" de Mastercard.

### ¿Qué es 3DS?

EMVCo, junto con las principales marcas y administradoras de tarjetas, desarrolló EMV 3D-Secure (3DS): un protocolo que permite autenticar la identidad de quien compra con la entidad emisora de su tarjeta. Así se garantiza el correcto funcionamiento del ecosistema de pagos en el ámbito de la tarjeta no presente.

### ¿Qué exige Mastercard?

Por disposición de Mastercard Internacional, es mandatorio incorporar este protocolo a las ventas realizadas con esta tarjeta. Para hacerlo, los comercios y/o facilitadores de pago (payfacts) deben integrarse mediante las APIS de Fiserv y elegir una de estas modalidades: Data Only o EMV 3DS Full Authentication.

### Modalidades disponibles de 3DS

#### Data Only

El comercio o payfac comparte los datos de la persona titular de la tarjeta a Mastercard para nutrir al ecosistema de pagos y cumplir con el mandato vigente. Como la persona no tiene que realizar ningún desafío, no genera fricciones, aumentando la tasa de aprobación. Ante un desconocimiento de la operación (fraude), el comercio deberá afrontar el contracargo.

#### EMV 3DS Full Authentication

Antes de autorizar la venta, la entidad emisora autentica la identidad de la persona titular de la tarjeta pudiendo solicitarle que realice un desafío. Como el emisor es quien realiza la autenticación, asume la responsabilidad ante el desconocimiento de la operación. Esto ofrece Liability Shift (resguardo ante contracargos) si se autentican las transacciones teniendo en cuenta estos códigos de respuesta:

| Código de Respuesta 3DS | Caso de uso | Liability Shift |
| --- | --- | --- |
| 1 | Fully authenticated transaction (with CAVV/AVV) | Sí |
| 3 | Auth Failure (rejected by DS or ACS) | No (la transacción no se autorizará) |
| 4 | Attemp (successful attempt to authenticate the cardholder in case the cardholder failed to register on their issuer´s portals) | Sí |
| 5 | Unable to authenticate due to an error received from DS - used for 3DS v1 protocol | No |
| 6 | Unable to authenticate (the authentication is not possible on ACS or DS side) | No |
| 7 | Auth Failure (credit card not enrolled in DS) - used for 3DS v1 protocol | No |
| 8 | Invalid authentication elements values or combination | No |
| A | Successful Mastercard Insights / Data Only transaction | No |
| B | Unsuccessful Mastercard Insights / Data Only transaction | No |

### Diferencias entre EMV 3DS Full y 3DS Data Only

> **Reconstruida a partir de la página renderizada.** El cuadro original marca cada celda con un tilde gráfico que no sobrevive a la extracción de texto; además el orden de las columnas que devolvía la extracción no era el real. Esta versión se transcribió mirando la página.

| | Experiencia sin fricción | Influir en la decisión de aprobación del emisor | Sin retraso en la transacción | Liability Shift | Evaluación de riesgos en tiempo real |
| --- | --- | --- | --- | --- | --- |
| **3DS Data Only** | Sí | Sí | Sí | — | Sí |
| **EMV 3DS Full Authentication** | Posibilidad de un desafío | Sí | — | Sí | Sí |

### Costos del servicio

Desde el 1 de febrero de 2023, Fiserv factura al comercio o Payfac el SEF y el Servicio 3DS, según corresponda.

| | 3DS Data Only | EMV 3DS Full Authentication |
| --- | --- | --- |
| **Mastercard** | Sin cargo. Si se desconoce la transacción, el comercio será quien asuma el contracargo. | 0,025% de la transacción con tope equivalente a USD 3*. No incluye IVA. |
| **Visa** | — | Sin cargo. El servicio es opcional. |

> **Nota de conversión:** en el PDF original esta información está en dos recuadros; el de "EMV 3DS Full Authentication" se subdivide por marca con los logos de Mastercard y Visa. La tabla de arriba se reconstruyó mirando la página renderizada, porque la extracción de texto plana fusionaba ambas filas y hacía parecer que el servicio era a la vez arancelado y sin cargo.

#### Cargo por incumplimiento: Security Enhacement Fee (SEF)

Mastercard establece un precio fijo de 0,025% por transacción no autenticada, con un tope de USD 3.

*Se factura en la liquidación diaria de transacciones, en pesos argentinos y según la cotización del dólar provista por el Banco Nación. El cobro se identifica con el nombre "Cargo 3DS MC". Aplica el IVA y otros impuestos previstos por Ley.

### Contactanos

Informale a tu Ejecutivo/a comercial qué modalidad de 3DS querés para avanzar con la integración del servicio.


---

# Parte 6 — Pagos recurrentes y Card on File

Escenarios CIT/MIT, initial y subsequent, por marca y por tipo de tokenización.

## 11. Pagos recurrentes

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §11*

Los pagos recurrentes (Recurring Payments) son transacciones en las que un consumidor autoriza a un comerciante a debitar su cuenta o tarjeta de crédito de forma regular para pagar por bienes o servicios que se reciben de manera continua. Este método de pago es común en servicios como suscripciones mensuales a plataformas de streaming, membresías de gimnasios, servicios de software, entre otros.

### 11.1 Parámetros de Pagos Recurrentes

Las transacciones de pagos recurrentes deben incluir ciertos parámetros para ser consideradas como tales:

| Parámetro | Descripción |
| --- | --- |
| recurringType | En la primera transacción debe informarse el valor FIRST. Para las transacciones siguientes debe enviarse el valor REPEAT. |
| CustomerID | Valor con el que el comercio identifica al cliente |
| invoicePeriod | Valor mediante el cual se informa el periodo debitado. Debe informarse bajo el formato MM/AA |
| TokenCryptogram | Valor criptográfico generado por el emisor o el sistema de tokenización, que autentica el uso del token en la transacción. Se utiliza en la transacción FIRST dentro del flujo passthrough de Network Tokenization. |
| SchemeTransactionId | Identificador único de la transacción asignado por la marca de la tarjeta y que debe ser almacenado por el comercio para futuras referencias. Aplicable para transacciones con la marca VISA. |
| ReferencedSchemeTransactionId | Campo que debe contener el SchemeTransactionId de la transacción FIRST. Se utiliza en las transacciones REPEAT para vincularlas con la transacción original. Aplicable para transacciones con la marca VISA. |

### 11.2 Recurrencia y Card on File

En el contexto de pagos recurrentes, la funcionalidad de tokenización permite almacenar de forma segura los datos de la tarjeta del cliente, reemplazándolos por un token que puede ser reutilizado en futuras transacciones. Este modelo se enmarca en el esquema Card on File (CoF), donde el comercio conserva el token asociado a la tarjeta para facilitar cobros periódicos sin necesidad de que el cliente vuelva a ingresar sus datos.

Las transacciones recurrentes se dividen en dos etapas principales:

- **Transacción FIRST**: es la primera transacción del ciclo recurrente. En esta operación debe tenerse en cuenta lo siguiente para cada marca:
  - **VISA**: en la respuesta de la transacción el comercio recibirá un identificador de la transacción original (SchemeTransactionId). Este identificador debe ser almacenado por el comercio, ya que será necesario para las transacciones siguientes. Si la transacción fue realizada con tokenización de marca (Network Tokenization), debe enviarse el criptograma.
  - **Mastercard**: debe adicionarse los parámetros de 3DS Data Only. Asimismo, si la transacción fue realizada con tokenización de marca (Network Tokenization), debe enviarse el criptograma.

- **Transacción REPEAT**: son las transacciones subsiguientes dentro del ciclo recurrente. Nuevamente, lo que ha de tenerse en cuenta para estas transacciones, según la marca, es lo siguiente:
  - **VISA**: debe informarse el valor recibido en el parámetro SchemeTransactionId de la transacción original, en el campo ReferencedSchemeTransactionId. Si la transacción fue realizada con tokenización de marca (Network Tokenization), no hará falta enviar el criptograma en las transacciones de tipo REPEAT.
  - **Mastercard**: deben enviarse sin 3DS. Si la transacción fue realizada con tokenización de marca (Network Tokenization), no hará falta enviar el criptograma en las transacciones de tipo REPEAT.

Además, según el modelo CoF existen dos tipos de transacciones:

- **CIT (Cardholder Initiated Transaction)**: Iniciadas por el titular de la tarjetas.
- **MIT (Merchant Initiated Transaction)**: Iniciadas por el comercio, como parte de un acuerdo preexistente (por ejemplo, suscripciones o pagos automáticos), y no requieren la participación directa del cliente en el momento de la transacción.

Esta estructura permite a los comercios automatizar cobros periódicos de forma segura y conforme a los estándares de las marcas de tarjetas.

Además, en el caso de pagos recurrentes, al tratarse de transacciones iniciadas por el comercio, debe informarse el parámetro MIT. Por ahora, este parámetro está disponible para la marca Mastercard.

### 11.3 Pagos Recurrentes: transacciones

#### 11.3.1 Pagos recurrentes con Tokens IPG

Ejemplo de mensaje para una transacción de Pagos Recurrentes:

##### 11.3.1.1 VISA

**a. Transacción FIRST:**

```json
{
    "transactionAmount": {
       "total": "110.00",
       "currency": "ARS"
    },
    "requestType": "PaymentTokenSaleTransaction",
    "storeId": "5923080904",
    "paymentMethod": {
       "paymentToken": {
          "tokenOriginStoreId": "5923080904",
          "value": "C70D810A-0187-491E-BAC1-22AD35984B72"
       }
    },
    "order": {
       "billing": {
          "customerId": "12345678"
       },
       "installmentOptions": {
          "recurringType": "FIRST"
       },
       "additionalDetails": {
          "invoicePeriod": "08/25"
       }
    }
}
```

Este ejemplo es de una primera transacción de tipo pago recurrente, por ello el valor del parámetro “recurringType” es FIRST. Para las siguientes transacciones de esta recurrencia debe enviarse el valor REPEAT.

En el response de IPG se informará el Transaction ID (de la marca) en el campo SchemeTransactionId. El comercio debe guardar el SchemeTransactionId, y relacionarlo con la recurrencia que va a establecer, enviándolo en las transacciones recurrentes posteriores en el campo referencedSchemeTransactionId:

**b. Transacción REPEAT:**

```json
{
    "transactionAmount": {
       "total": "110.00",
       "currency": "ARS"
    },
    "requestType": "PaymentTokenSaleTransaction",
    "storeId": "5923080904",
    "paymentMethod": {
       "paymentToken": {
          "tokenOriginStoreId": "5923080904",
          "value": "C70D810A-0187-491E-BAC1-22AD35984B72"
       }
    },
    "order": {
       "billing": {
          "customerId": "12345678"
       },
       "installmentOptions": {
          "recurringType": "REPEAT"
       },
       "additionalDetails": {
          "invoicePeriod": "08/25"
       }
    },
    "storedCredentials": {
       "sequence": "SUBSEQUENT",
       "scheduled": false,
       "referencedSchemeTransactionId": "098765432112345"
    }
}
```

##### 11.3.1.2 Mastercard

**a. Transacción FIRST:**

```json
{
   "transactionAmount": {
      "total": "110.00",
      "currency": "ARS"
   },
   "requestType": "PaymentTokenSaleTransaction",
   "storeId": "5923080904",
   "paymentMethod": {
      "paymentToken": {
         "tokenOriginStoreId": "5923080904",
         "value": "C70D810A-0187-491E-BAC1-22AD35984B72"
       }
    },
    "order": {
       "billing": {
          "customerId": "12345678"
       },
       "installmentOptions": {
          "recurringType": "FIRST"
       },
       "additionalDetails": {
          "invoicePeriod": "08/25"
       }
    },

  "storedCredentials": {
     "sequence": "FIRST",
     "scheduled": false,
     "initiator": "MERCHANT",
     "indicatorSubcategory": "CREDENTIAL_ON_FILE_FIRST"
  },
  "authenticationRequest": {
     "authenticationType": "Secure3DAuthenticationRequest",
     "messageCategory": "80",
     "methodNotificationURL" : "https://webhook.site/065191be-0702-46ae-a949-9b6730b4ac06",
     "termURL" : "https://webhook.site/065191be-0702-46ae-a949-9b6730b4ac06"
  }
}
```

Este ejemplo es de una primera transacción de tipo pago recurrente, por ello el valor del parámetro “recurringType” es FIRST. Para las siguientes transacciones de esta recurrencia debe enviarse el valor REPEAT.

Debe adicionarse la mensajería correspondiente a una transacción de tipo Card on File iniciada por el comercio (Merchant Initiated Transaction).

**b. Transacción REPEAT:**

```json
{
    "transactionAmount": {
         "total": "110.00",
         "currency": "ARS"
    },
    "requestType": "PaymentTokenSaleTransaction",
    "storeId": "5923080904",
    "paymentMethod": {
         "paymentToken": {
              "tokenOriginStoreId": "5923080904",
              "value": "C70D810A-0187-491E-BAC1-22AD35984B72"
         }
    },
    "order": {
         "billing": {
              "customerId": "12345678"
         },
         "installmentOptions": {
              "recurringType": "REPEAT"
         },
         "additionalDetails": {
              "invoicePeriod": "08/25"
         }
    },

    "storedCredentials": {
         "sequence": "SUBSEQUENT",
         "scheduled": false,
         "initiator": "MERCHANT",
         "indicatorSubcategory": "CREDENTIAL_ON_FILE_FIRST"
    }
}
```

#### 11.3.2 Pagos recurrentes con Tokenización Passthrough

Ejemplo de mensaje para una transacción de Pagos Recurrentes:

##### 11.3.2.1 VISA

**a. Transacción FIRST:**

```json
{
    "requestType": "PaymentCardSaleTransaction",
    "storeId": "5923080904",
    "transactionAmount": {
       "total": "102.00",
       "currency": "ARS"
    },
    "paymentMethod": {
       "paymentCard": {
          "number": "4044710000000004",
          "expiryDate": {
              "month": "12",
              "year": "29"
          }
       }
    },
    "order": {
       "tokenRequestorID": "12345678912",
       "tokenECI": "05",
       "billing": {
          "customerId": "12345678"
       },
       "installmentOptions": {
          "recurringType": "FIRST"
       },
       "additionalDetails": {
          "invoicePeriod": "08/25"
       },
       "tokenCryptogram": "AgAAAAoAPlUosiUEDQNSgElQEAA="
    }
}
```

Este ejemplo es de una primera transacción de tipo pago recurrente, por ello el valor del parámetro “recurringType” es FIRST. Para las siguientes transacciones de esta recurrencia debe enviarse el valor REPEAT.

En el response de IPG se informará el Transaction ID (de la marca) en el campo SchemeTransactionId. El comercio debe guardar el SchemeTransactionId, y relacionarlo con la recurrencia que va a establecer, enviándolo en las transacciones recurrentes posteriores en el campo referencedSchemeTransactionId:

**b. Transacción REPEAT:**

```json
{
    "requestType": "PaymentCardSaleTransaction",
    "storeId": "5923080904",
    "transactionAmount": {
       "total": "102.00",
       "currency": "ARS"
    },
    "paymentMethod": {
       "paymentCard": {
          "number": "4044710000000004",
          "expiryDate": {
              "month": "12",
              "year": "29"
          }
       }
    },
    "order": {
       "tokenRequestorID": "12345678912",
       "tokenECI": "05",
       "billing": {
          "customerId": "12345678"
       },
       "installmentOptions": {
          "recurringType": "REPEAT"
       },
       "additionalDetails": {
          "invoicePeriod": "08/25"
       },
       "tokenCryptogram": "AgAAAAoAPlUosiUEDQNSgElQEAA="
    },
    "storedCredentials": {
       "sequence": "SUBSEQUENT",
       "scheduled": false,
       "referencedSchemeTransactionId": "098765432112345"
    }
}
```

##### 11.3.2.2 Mastercard

**a. Transacción FIRST:**

```json
{
  "requestType": "PaymentCardSaleTransaction",
  "storeId": "5923080904",
  "transactionAmount": {
     "total": "102.00",
     "currency": "ARS"
  },
  "paymentMethod": {
     "paymentCard": {
        "number": "5165850000000008",
        "expiryDate": {
            "month": "12",
            "year": "29"
        }
     }
  },
  "order": {
     "tokenRequestorID": "12345678912",
     "tokenECI": "05",
     "billing": {
        "customerId": "12345678"
     },
     "installmentOptions": {
        "recurringType": "FIRST"
     },
     "additionalDetails": {
        "invoicePeriod": "08/25"
     },
     "tokenCryptogram": "AgAAAAoAPlUosiUEDQNSgElQEAA="
  },
  "storedCredentials": {
     "sequence": "FIRST",
     "scheduled": false,
     "initiator": "MERCHANT",
     "indicatorSubcategory": "CREDENTIAL_ON_FILE_FIRST"
  },
  "authenticationRequest": {
     "authenticationType": "Secure3DAuthenticationRequest",
     "messageCategory": "80",
     "methodNotificationURL": "https://webhook.site/065191be-0702-46ae-a949-9b6730b4ac06",
     "termURL": "https://webhook.site/065191be-0702-46ae-a949-9b6730b4ac06"
  }
}
```

Este ejemplo es de una primera transacción de tipo pago recurrente, por ello el valor del parámetro “recurringType” es FIRST. Para las siguientes transacciones de esta recurrencia debe enviarse el valor REPEAT.

Debe adicionarse la mensajería correspondiente a una transacción de tipo Card on File iniciada por el comercio (Merchant Initiated Transaction).

**b. Transacción REPEAT:**

```json
{
    "requestType": "PaymentCardSaleTransaction",
    "storeId": "5923080904",
    "transactionAmount": {
       "total": "102.00",
       "currency": "ARS"
    },
    "paymentMethod": {
       "paymentCard": {
          "number": "5165850000000008",
          "expiryDate": {
              "month": "12",
              "year": "29"
          }
       }
    },
    "order": {
       "tokenRequestorID": "12345678912",
       "tokenECI": "05",
       "billing": {
          "customerId": "12345678"
       },
       "installmentOptions": {
          "recurringType": "REPEAT"
       },
       "additionalDetails": {
          "invoicePeriod": "08/25"
       },
       "tokenCryptogram": "AgAAAAoAPlUosiUEDQNSgElQEAA="
    },
    "storedCredentials": {
       "sequence": "SUBSEQUENT",
       "scheduled": false,
       "initiator": "MERCHANT",
       "indicatorSubcategory": "CREDENTIAL_ON_FILE_FIRST"
    },
    "authenticationRequest": {
    "authenticationType": "Secure3DAuthenticationRequest",
    "messageCategory": "80",
    "methodNotificationURL": "https://webhook.site/065191be-0702-46ae-a949-9b6730b4ac06",
    "termURL": "https://webhook.site/065191be-0702-46ae-a949-9b6730b4ac06"
  }
}
```

\*Los campos tokenRequestorID y tokenECI son opcionales. Si el comercio obtuvo network tokens autenticados, IPG de Fiserv está habilitado para recibir dichas transacciones. Estos campos son requeridos para esta casuística.


---

# Parte 7 — Payment Facilitator, Tax Refund y Wallet

Módulos adicionales: sub-merchants, devolución de impuestos (UY) y wallet.

## 12. Payment Facilitator

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §12*

Los Payment Facilitator (PFAC) juegan un rol muy importante en el desarrollo del eCommerce. El sostenido crecimiento de la actividad de los PFAC, ha llevado a las marcas a requerirle cada vez mas información a sus adquirentes, con la finalidad de controlar posibles malos usos de esta figura, como ser la actividad de Cross border realizada por alguno de sus submerchant o la realización de transacciones con un ramo o rubro indebido (MCC).

Las marcas definieron marcos regulatorios de la Actividad para los PFAC, que incluyen la aplicación de multas para los casos donde se comprueben incumplimientos a las normas fijadas. El Programa PIFO para las operaciones con MCW y el programa EMLP para las operaciones con VISA.

A fin de evitar la aplicación de estas penalidades, FISERV requiere que todo PFAC que opere en su adquirencia cumpla con el envío de la información que se detalla a continuación, en cada transacción de cobro que realice dentro de los programas PIFO y EMLP. En caso de detectar alguna inconsistencia en la información, FISERV podrá no cursar la transacción de autorización a la marca, devolviendo un rechazo al Comercio. Y si la inconsistencia no fuese detectada por FISERV y se generasen penalidades desde la Marca por la información errónea suministrada, las mismas serán trasladadas al PFAC.

Asimismo, el PFAC acepta incluir cualquier nuevo requerimiento de información que FISERV o las marcas soliciten, en virtud de su actividad, o de cualquiera de sus clientes (submerchants).

El PFAC deberá registrarse o bien otorga a FISERV el consentimiento para registrarlo en las plataformas de cada Marca para obtener el PFAC_ID que lo identificará en toda la operatoria.

### Condiciones

En la operación de un PFAC las Marcas requieren determinar la actividad de los submerchants a los que presta servicio. En muchos casos, la marca nos ha informado que el MCC enviado por el PFAC es incorrecto lo que genera la violación a reglas propias de la marca con su consecuente multa.

Para regularizar esta situación, se debe informar a la marca en la mensajería, el MCC (Merchant Category Code) que refleja el negocio principal del Submerchant.

El MCC refleja la actividad/RAMO del comercio que pide la autorización y se encuentra asociado al MID (Merchant ID es el número de Comercio con el que se pide la autorización) del PFAC.

Fiserv proporcionará al PFAC los diferentes MID y Store_ID asociados, que son necesarios para cubrir la actividad de los RAMOS habilitados para E-commerce. De esta forma el PFAC deberá rutear debidamente a través de estos Store_ID las operaciones de sus submerchant según el RAMO de cada uno.

Dicha información, MIDs y Store_ID asociados, deberán ser solicitados a su Account Operativo y/o Equipo de BO según aplique a fin de enviar correctamente los MCCs habilitados a través de los Stores. El mismo MCC deberá ser enviado como MCC del Merchant así como en el MCC del Submerchant.

Esta condición es de carácter mandatorio por parte de Fiserv a fin de evitar multas por parte de las marcas y aplica tanto para los PFACs que están iniciando su relación con Fiserv bajo la figura de un PFAC, así como en caso de ya encontrarse operando bajo dicha figura a través de Fiserv.

De acuerdo con lo estipulado en el contrato de servicio de Adquirencia/Contrato de servicios de facilitador de pago/reglamento operativo, según aplique, en caso de generar un incumplimiento de esta condición y por consecuencia una penalidad ante la marca, se trasladarán dichas penalidades al PFAC a través de la liquidación.

### 12.1 Boarding

Durante el proceso de onboarding debe tener a la mano el siguiente dato, que lo identifica como Payment Facilitator ante las marcas:

- paymentFacilitatorId

Es necesario contar con un paymentFacilitatorID para Visa y uno para Mastercard, respectivamente, para poder operar con cada una de estas marcas.

### 12.2 Campos obligatorios

Los siguientes campos son obligatorios como parte de la mensajería de una transacción de un Payment Facilitator. Debe tenerse en cuenta que si el Submerchant es local, se envía la información del Submerchan; si el Submerchant es internacional, se envía la información del PFAC en los campos del submerchant:

| Path/Name | XML Schema type | Value | Observaciones |
| --- | --- | --- | --- |
| mcc | xs:string | Merchant Category Code | Actividad del Sub merchant o comercio cliente del PFAC. Para conocer los MCC, Puede solicitar apoyo a su account operativo. |
| legalName | xs:string | Razón Social del subcomercio. | Nombre legal del Submercant |
| merchantId | xs:string |  | ID único que identifica univocamente al Submerchant en el PFAC Dato generado por el PFAC. |
| address1 | xs:string | Direccion física (o legal) del Submerchant. Una linea | Direccion física (o legal) del Submerchant. Una linea |
| city | xs:string | Ciudad | Ciudad |
| postalCode | xs:string | Código Postal | El CP debe enviarse bajo el formato AAA1234BB. |
| region | xs:string | País | ISO 3166-1 |
| country | xs:string | País | ISO 3166-1 |
| type | xs:string | Tipo de documento del SubMerchant | Tipo de documento del SubMerchant |
| number | xs:string | Número de documento del submerchant | Número de documento del submerchant |
| DynamicMerchantName | xs:string |  | SoftDescriptor. El prefijo PFAC será asignado por FISERV durante la integración. |

### 12.3 Request y Response

Ejemplo de Request:

```json
{
     "requestType": "PaymentCardSaleTransaction",
     "transactionAmount": {
          "total": 10,
          "currency": "ARS"
     },
     "storeId": "5923080904",
     "paymentMethod": {
          "paymentCard": {
            "number": {{test_card}},
            "securityCode": "123",
            "expiryDate": {
               "month": "12",
               "year": "29"
              }
         },
         "paymentFacilitator": {
              "subMerchantData": {
                  "mcc": "5999",
                  "legalName": "la tiendita SRL",
                  "address": {
                       "company": "La tiendita",
                       "address1": "San martin 346",
                       "city": "La plata",
                       "region": "ARG",
                       "postalCode": "AAA1234BB",
                       "country": "ARG"
                  },
                  "document": {
                       "type": "SINGLE_TAX_IDENTIFICATION",
                       "number": "12345678"
                  },
                  "merchantId": "Identificador01"
              }
         }
    },
    "order": {
         "softDescriptor": {
              "dynamicMerchantName": "PFAC123*Submerchat"
         }
    }
}
```

## Apéndice VII. Payment Facilitator (parámetros mandatories y opcionales)

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §Apéndice VII*

**Transacciones de autenticación**

| | |
| --- | --- |
| requestType posibles (siempre mandatorio) | PaymentCardSaleTransaction<br>PaymentCardPreAuthTransaction |
| Campos mandatorios adicionales para PFAC | PaymentMethod/paymentFacilitator/externalMerchantId<br>PaymentMethod/paymentFacilitator/paymentFacilitatorId<br>PaymentMethod/paymentFacilitator/name<br>PaymentMethod/paymentFacilitator/subMerchantData/mcc<br>PaymentMethod/paymentFacilitator/subMerchantData/legalname<br>PaymentMethod/paymentFacilitator/subMerchantData/Address/address1<br>PaymentMethod/paymentFacilitator/subMerchantData/Address/city<br>PaymentMethod/paymentFacilitator/subMerchantData/Address/region *<br>PaymentMethod/paymentFacilitator/subMerchantData/Address/postalCode<br>PaymentMethod/paymentFacilitator/subMerchantData/Address/country<br>PaymentMethod/paymentFacilitator/subMerchantData/Document/Type<br>PaymentMethod/paymentFacilitator/subMerchantData/Document/number<br>PaymentMethod/paymentFacilitator/subMerchantData/merchantId<br>SoftDescriptor/dinamycMerchantName<br>Parámetros mandatorios de la transacción primaria elegida ** |
| Campos opcionales adicionales para PFAC | PaymentMethod/paymentFacilitator/subMerchantData/Address/address2 |

\* Mandatorio si Country = USA

\*\* Deben adicionarse al resto de los campos mandatorios de la transacción elegida (PaymentCardSaleTransaction o PaymentCardPreAuthTransaction).

## 13. Tax Refund Uruguay

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §13*

Uruguay tiene leyes especiales de devolución de impuestos y, según la ley, se debe enviar un valor diferente en cada caso. Los posibles valores son los siguientes:

- NO_TAX_REFUND
- URY_RETURNS_IVA_LAW_17934
- URY_RETURNS_IMESI_LAW_18083
- URY_RETURNS_AFAM_LAW_18910
- URY_TAX_REFUND_LAW_18999
- URY_RETURNS_IVA_LAW_19210

Un ejemplo de cómo agregar estos campos se puede ver a continuación:

```json
{
    "transactionAmount": {
         "total": "122.00",
         "currency": "UYU",
         "components": {
             "subtotal": "100",
             "vatAmount": "22",
             "tip": "0",
             "surcharge": "0"
         }
    },
    "storeId": "7732456167",
    "paymentMethod": {
         "paymentCard": {
             "number": 5204736190003097,
             "securityCode": "XXX",
             "expiryDate": {
                 "month": "12",
                 "year": "29"
             }
         }
    },
    "requestType": "PaymentCardSaleTransaction",
    "order": {
        "additionalDetails": {
            "taxRefundRequestData": {
                "legalFramework": "URY_RETURNS_IVA_LAW_19210"
            }
        }
    }
}
```

## 15. Wallet

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §15*

Todas las transacciones originadas desde un QR y que serán finalizadas desde una Wallet deben incluir los parámetros adicionales de los siguientes casos:

**Transacción con PAN**

```json
{
  "requestType": "WalletSaleTransaction",
  "storeId": "5923080904",
  "transactionAmount": {
     "total": "1186",
     "currency": "ARS"
  },
  "walletPaymentMethod": {
     "walletType": "DecryptedLatamQRWalletPaymentMethod",
     "decryptedLatamQRWallet": {
        "accountNumber": "4123229999000226",
        "cardCodeValue": "462",
        "expiration": {
           "month": "12",
           "year": "31"
        },
        "walletId": "MODO",
        "walletName": "MODO",
        "walletTransactionId": "012",
        "walletTransactionType": "DYNAMIC_QR_CARD_PAYMENT"
     }
  }
}
```

**Transacción con Network Token (Passthrough)**

```json
{
  "requestType": "WalletSaleTransaction",
  "transactionAmount": {
     "total": "1901",
     "currency": "UYU"
  },
  "order": {
     "tokenCryptogram": "kBAYYgZVLBwEl08klDyU79WE6XqM",
     "tokenRequestorID": "50106190476"
  },
  "walletPaymentMethod": {
     "walletType": "DecryptedLatamQRWalletPaymentMethod",
     "decryptedLatamQRWallet": {
        "accountNumber": "5101980000001115",
        "expiration": {
           "month": "12",
           "year": "31"
        },
        "walletId":"858",
        "walletName":"MODO",
        "walletTransactionId":"901",
        "walletTransactionType": "DYNAMIC_QR_CARD_PAYMENT"
     }
  }
}
```


---

# Parte 8 — Manejo de errores, rechazos y reintentos

Qué devuelve el gateway cuando algo falla, cómo interpretarlo y qué reintentos están penalizados por las marcas.

## Códigos de rechazo (declined / failed)

*Fuente: Códigos-rechazo-declined-failed.pdf*

Códigos de rechazo — Declined y Failed

### Códigos DECLINED

| Processor Response Code | IPG_APPROVAL_CODE | Importe para simular el error |
| --- | --- | --- |
| 1 | N:01:Refer to card issuer | 1001 |
| 2 | N:02:Refer to special conditions for card issuer | 1002 |
| 3 | N:03:Invalid merchant | 1003 |
| 4 | N:04:Pick - up card | 1004 |
| 5 | N:05:Do not honour | 1005 |
| 7 | N:07:Pick-up card, special condition | 1007 |
| 12 | N:12:Invalid transaction | 1012 |
| 13 | N:13:Invalid amount | 1013 |
| 14 | N:14:Invalid card number (no such number) | 1014 |
| 15 | N:15:No such issuer / Emisor Invalido | |
| 19 | N:19:Unknown Response Code | |
| 25 | N:25:Record not found in transaction file | |
| 30 | N:30:Format error | 1030 |
| 31 | N:31:Card not supported | 1031 |
| 33 | N:33:Expired card | |
| 36 | N:36:Restricted card | |
| 38 | N:38:Allowable PIN tries exceeded | 1038 |
| 41 | N:41:Lost card | |
| 43 | N:43:Stolen card | 1043 |
| 45 | N:45:The card can't operate with installments | 1045 |
| 46 | N:46:Card expired | 1046 |
| 47 | N:47:The card needs a pin | 1047 |
| 48 | N:48:Exceed max limit installments | 1048 |
| 49 | N:49:Check the system | 1049 |
| 50 | N:50:The amount is out of range allowed | 1050 |
| 51 | N:51:Not sufficient fund | 1051 |
| 53 | N:53:Not savings account | |
| 54 | N:54:Expired card | 1054 |
| 55 | N:55:Incorrect personal identification number | 1055 |
| 56 | N:56:No card record | 1056 |
| 57 | N:57:Transaction not permitted to cardholder | 1057 |
| 58 | N:58:Transaction not permitted to terminal | 1058 |
| 61 | N:61:Exceeds withdrawal amount limit | 1061 |
| 62 | N:62:Restricted card | |
| 65 | N:65:Exceeds withdrawal frequency limit | 1065 |
| 68 | N:68:Response received too late | |
| 75 | N:75:Allowable number of PIN tries exceeded | |
| 76 | N:76:Request phone authorization | 1076 |
| 77 | N:77:Approved | 1077 |
| 78 | N:78:Approved | |
| 79 | N:79:Approved | |
| 80 | N:80:Approved | |
| 81 | N:81:Approved | |
| 82 | N:82:Private,no security box | |
| 83 | N:83:Private (No Accounts) | |
| 84 | N:84:No pbf | |
| 85 | N:85:Issue ticket | |
| 86 | N:86:Invalid auth type | |
| 87 | N:87:Bad TRACK2 | |
| 88 | N:88:Private PTLF error | |
| 89 | N:89:The number of terminal is not available for issuer | 1089 |
| 91 | N:91:Issuer or switch is inoperative | 1091 |
| 94 | N:94:Duplicate transaction | 1094 |
| 96 | N:96:System malfunction | 1096 |
| 98 | N:98:Format error in additional data field | |
| 99 | N:99:Unknown Response Code | |
| N0 | N:N0:Unable to Authorize | |
| N1 | N:N1:Invalid PAN length | |
| N2 | N:N2:Preauth full | |
| N3 | N:N3:Private max online refund reached | |
| N4 | N:N4:Private max offline refund reached | |
| N5 | N:N5:Private max credit per refund | |
| N6 | N:N6:Max refund credit reached | |
| N7 | N:N7:Customer selected neg reason | |
| N8 | N:N8:Overfloor limit | |
| N9 | N:N9:Max number of refund credit | |
| O1 | N:O1:Neg file problem | |
| O2 | N:O2:Advance is less than min | |
| O3 | N:O3:Delinquent | |
| O4 | N:O4:Over limit table | |
| O5 | N:O5:Authentication may improve likelihood of an approval - retry using authentication | |
| O6 | N:O6:Suspected Fraud. Do not retry | |
| O7 | N:O7:Force post | |
| O8 | N:O8:Do not retry | |
| O9 | N:O9:Neg file problem | |
| P0 | N:P0:CAF file problem | |
| P1 | N:P1:Over Daily limit | |
| P2 | N:P2:CAPF not found | |
| P3 | N:P3:Advance is less than min | |
| P4 | N:P4:Number of times used exceeded | |
| P5 | N:P5:Delinquent | |
| P6 | N:P6:Over limit table | |
| P7 | N:P7:Advance less amount | |
| P8 | N:P8:Admin card needed | |
| P9 | N:P9:Enter lesser amount | |
| Q0 | N:Q0:Invalid transaction date | |
| Q1 | N:Q1:Invalid expirtation date | |
| Q3 | N:Q3:Advance is less than min | |
| Q4 | N:Q4:Number of times used exceeded | |
| Q5 | N:Q5:Delinquent | |
| Q6 | N:Q6:Over limit table | |
| Q7 | N:Q7:Amount over MAX | |
| Q8 | N:Q8:Admin card not found | |
| Q9 | N:Q9:Admin card not allowed | |
| R0 | N:R0:APPROVED admin request in window | |
| R1 | N:R1:APPROVED admin request out window | |
| R2 | N:R2:APPROVED admin request anytime | |
| R3 | N:R3:Chargeback customer file updated | |
| R4 | N:R4:Chargeback customer file updated. Acquirer not found | |
| R5 | N:R5:Chargeback incorrect prefix number | |
| R6 | N:R6:Chargeback incorrect response code or CPF CON | |
| R7 | N:R7:Admin transactions not supported | |
| R8 | N:R8:Private card on nation neg file | |
| S4 | N:S4:PTLF full | |
| S5 | N:S5:APPROVED, customer files not updated | |
| S6 | N:S6:APPROVED, files not updated Acquirer not found | |
| S7 | N:S7:ACCEPTED, incorrect Destination | |
| S8 | N:S8:Admin file error | |
| S9 | N:S9:Security device error | |
| T1 | N:T1:Invalid amount | |
| T2 | N:T2:Format error | |
| T3 | N:T3:No card record | |
| T4 | N:T4:Invalid amount | |
| T5 | N:T5:Check for New information before retry | |
| T6 | N:T6:Bad UAF | |
| T7 | N:T7:Cashback over daily limit | |

### Códigos FAILED

| IPG APROVAL CODE: FAILED | Descripción |
| --- | --- |
| N:-100:Internal error | An error occurred building, parsing or interpreting the message. |
| N:-10501:invalid postauth attempt | PostAuth already performed |
| N:-10501:PostAuth already performed | PostAuth already performed |
| N:-10601:Total amount passed is more than the Return/Void amount. | Total amount passed is more than the Return/Void amount. |
| N:-11101:installment not supported | Installment only supported for local cards |
| N:-11106:invalid invoice number | Invalid invoice number, only numeric value is allowed |
| N:-11107:invalid transaction/action type | Invalid transaction/action type, not allowed for this protocol |
| N:-11109:invalid merchant configuration | Missing Merchant Category Code (MCC) |
| N:-12000:Card security code is mandatory | The merchant has the service entry CardCodeMandatory, but sent a MOTO/ECI trx without card code value merchant info: 12000/Card security code is mandatory |
| N:-30031:No terminal found | No free terminal found. The merchant might need more terminals, because this decline happens when all terminals are busy / locked |
| N:-30031:No terminal setup | Missing terminal configuration for this transaction. |
| N:-30050:Communication Error | The transaction timed out. Exception occurred retrieving the message from the endpoint. |
| N:-30050:Transaction timed out | The transaction timed out. Exception occurred retrieving the message from the endpoint. |
| N:-30051:Transaction timed out | The transaction timed out. Exception occurred retrieving the message from the endpoint. |
| N:-30052:Communication Error | The transaction timed out. Exception occurred retrieving the message from the endpoint. |
| N:-30052:Transaction timed out | The transaction timed out. Exception occurred retrieving the message from the endpoint. |
| N:-30053:Communication Error | The transaction timed out. Exception occurred retrieving the message from the endpoint. |
| N:-30053:Transaction timed out | The transaction timed out. Exception occurred retrieving the message from the endpoint. |
| N:-30054:Transaction timed out | The transaction timed out. Exception occurred retrieving the message from the endpoint. (timeout de endpoint) |
| N:-30055:Not configured for 3DSecure | Not configured for 3DSecure |
| N:-30056:Internal Error | Error within code which should not occur, please let development know |
| N:-30057:Communication Error | The transaction timed out. Exception occurred retrieving the message from the endpoint. |
| N:-30058:The transaction has been settled within this process. | The transaction has been settled within this process. |
| N:-30060:Internal Error | An error occurred building, parsing or interpreting the message. |
| N:-30100:Internal error | Problem with database access |
| N:-42325:Zero amount not supported | Transaction type return and postauth do not allow Zero amount |
| N:-43232:Card function not supported | Card function is not supported for the given card and brand type |
| N:-50004:Invalid transaction request | Hosted Data Id should not be present in request since Assign Token Flag is true |
| N:-5002:brand not supported | The merchant does not have a service entry for the card brand that has been used in the transaction request. |
| N:-5002:Recurring payments not supported | Recurring payments not supported |
| N:-5003:The order already exists in the database. | The order already exists in the database. |
| N:-5004:No authorized preauth found | No authorized preauth found |
| N:-5006:Transaction not found | Transaction not found |
| N:-5008:Order does not exist. | Order does not exist. |
| N:-5009:No transaction to return found | No transaction to return found |
| N:-5010:Hosted data was not found | Hosted data was not found |
| N:-5017:Voiding of returned transactions is not supported | Voiding of returned transactions is not supported |
| N:-5018:No transaction found for void | No transaction found for void |
| N:-5019:Transaction not voidable | Transaction not voidable |
| N:-5022:not voidable | The preauth is not voidable as long as there is a captured postauth - please void the postauth before |
| N:-50701:Zero amount not supported | Store not allowed for Zero amount transaction |
| N:-50704:Sub merchant data not supported | Sub merchant data not supported |
| N:-50716:3DSecure authentication failed | 3DSecure authentication failed |
| N:-5112:Debit card not authenticated | Debit card not authenticated |
| N:-5311:Installment not configured | Installment is not configured for store |
| N:-5314:Invalid number of installments | Invalid number for the field number of installments |
| N:-5992:Invalid credit card track data, track one is missing | Invalid credit card track data, track one is missing |
| N:-5994:The selected brand does not match the card number. | The selected brand does not match the card number. |
| N:-5995:order too old to be referenced | Cannot perform returns on old and expired orders |
| N:-5996:Invalid card type | The cardnumber cannot be assigned to a credit card brand. The card number either is invalid or the brand is unknown to the system |
| N:-5997:The maximum number of recurring transactions per order has been exceeded | The maximum number of recurring transactions per order has been exceeded |
| N:-5997:The maximum number of transactions per order has been exceeded | The maximum number of transactions per order has been exceeded |
| N:-5998:order currently being processed | Other transaction with same order id currently being processed |
| N:-69522:BIN not enabled for the promotion | BIN not enabled for the promotion |
| N:-7777:System too busy, please retry | System too busy, please retry |
| N:-7778:Transaction timed out, please retry | Transaction timed out, please retry |

### Estamos para ayudarte

Versión 1 (11.24) — soporte.IPG@fiserv.com

## Penalización por reintentos (Visa / Mastercard)

*Fuente: Penalizacion por Reintentos Visa - Master.pdf*

Estimado comercio:

Queremos recordarte que hemos realizado mejoras en nuestra plataforma de E-commerce: Posnet Gateway, para facilitar la comprensión de los rechazos emisores y reducir los reintentos excesivos.

Esto nos ayudará a evitar multas de la Marca al comercio.

A partir de mayo comenzamos a enviar nuevos campos en la mensajería que recibís.

Estos cambios están diseñados para una experiencia más fluida y eficiente, brindándote mayor conocimiento sobre los motivos de rechazo.

Te acercamos dos documentos para que puedas chequear las diferentes categorías en ambas Marcas:

> **[Imagen/diagrama en el documento original]** — enlaces o íconos de descarga de los dos documentos adjuntos (uno por Marca: Visa y Mastercard) con las categorías de rechazo; no se extrajeron en la conversión.

Muchas gracias. Equipo Fiserv.

### Aviso legal

Operar con www.fiserv.com.ar implica aceptar los Términos y Condiciones en los que es ofrecido. El presente mail ha sido enviado debido a que Ud. proporcionó su dirección de correo electrónico con el fin de que lo mantuviéramos informado sobre nuestros servicios actuales o futuros. No obstante, en el caso que Ud. no deseara continuar recibiendo e-mails con este tipo de información en el futuro, por favor ingrese a la sección "Alertas OnLine" y desactive la alerta destildando las opciones correspondientes. First Data Cono Sur S.R.L todos los derechos reservados. El contenido del presente mensaje es privado, estrictamente confidencial y exclusivo para sus destinatarios, pudiendo contener información protegida por normas legales y de secreto profesional. Bajo ninguna circunstancia su contenido puede ser transmitido o revelado a terceros ni divulgado en forma alguna. Disposición DNPDP 4-2009. Archivos, registros o bancos de datos con fines de publicidad. Art. 27 Inc. 3 Ley 25.326 El titular podrá en cualquier momento solicitar el retiro o bloqueo de su nombre de los bancos de datos a los que se refiere el presente artículo. Art. 27 Anexo I Decreto 1558/0. En toda comunicación con fines de publicidad que se realice por correo, teléfono, correo electrónico, Internet u otro medio a distancia a conocer, se deberá indicar, en forma expresa y destacada, la posibilidad del titular del dato de solicitar el retiro o bloqueo total o parcial, de su nombre de la base de datos. A pedido del interesado, se deberá informar el nombre del responsable o usuario del banco de datos que proveyó la información. Usted podrá solicitar el retiro o bloqueo total o parcial de su nombre de la base de datos a través de www.fiserv.com.ar a Consultas por e-mail. Disposición DNPDP 10-2008. El titular de los datos personales tiene la facultad de ejercer el derecho de acceso a los mismos en forma gratuita a intervalos no inferiores a seis meses, salvo que acredite un interés legítimo al efecto conforme lo establecido en el artículo 14, inciso 3 de la Ley 25.326. La DIRECCION NACIONAL DE PROTECCION DE DATOS PERSONALES, Organo de Control de la Ley 25.326, tiene la atribución de atender las denuncias y reclamos que se interpongan con relación al incumplimiento de las normas sobre protección de datos personales.


---

## Tabla de reintentos VISA (adjunto recuperado)

*Fuente: `TABLA_REINTENTOS_VISA_062024.pdf` — adjunto enlazado desde `Penalizacion por Reintentos Visa - Master.pdf` (https://destinab.ly/storage/fiserv/TABLA_REINTENTOS_VISA_062024.pdf). El archivo no estaba en la carpeta; se recuperó desde el enlace embebido en el PDF.*

En caso de exceder los reintentos permitidos, se aplicará un cargo de **USD 0,10\*** para las transacciones locales y **USD 0,25\*** para las transacciones internacionales, en base a las siguientes categorías:

| Categoría | Reintentos aceptados |
| --- | --- |
| 1 | Reintentos no permitidos |
| 2 | Hasta 15 reintentos permitidos en 30 días |
| 3 | Revalidar la información de pago antes de reintentar. Hasta 15 reintentos permitidos en 30 días. |
| 4 | Hasta 14 reintentos permitidos en 30 días. |

### Respuestas ISO VISA y su categoría de reintento

| ISO CODE | Descripción | Categoría |
| --- | --- | --- |
| 00 | Approved | — |
| 01 | Contact card issue | 4 |
| 02 | Contact card issue, special condition | 4 |
| 03 | Not approved. Invalid merchant | 2 |
| 04 | Not approved. Pick up card (no fraud) | 1 |
| 05 | Do not honor | 4 |
| 06 | Error | 4 |
| 07 | Not approved. Authentication not completed | 1 |
| 10 | Partial approval | — |
| 11 | Approved VIP | — |
| 12 | Invalid transaction | 1 |
| 13 | Invalid amount / Currency convertion field overflow | 4 |
| 14 | Invalid account number | 1 |
| 15 | No such issuer | 1 |
| 19 | Re-enter transaction | 2 |
| 21 | No action taken | 4 |
| 25 | Uneable to locate record in file | 4 |
| 28 | File is temporarily unavailable for update or inquiry | 4 |
| 39 | No credit account | 4 |
| 41 | Lost card, fraud account | 1 |
| 43 | Stolen card, fraud account | 1 |
| 46 | Closed account | 1 |
| 51 | Not sufficient funds | 2 |
| 52 | No checking account | 4 |
| 53 | No savings account | 4 |
| 54 | Expired card or expiration date missing | 3 |
| 55 | Incorrect PIN | 3 |
| 57 | Transaction not permitted to cardholder | 1 |
| 58 | Transaction not allowed in this terminal | 4 |
| 59 | Suspected fraud | 2 |
| 61 | Exceeds limit approval amount | 2 |
| 62 | Restricted card (card invalid in region or country) | 2 |
| 63 | Security violation | 2 |
| 64 | Not approved. Transaction does not fulfill requirement | 4 |
| 65 | Exceeds limit of withdrawl frequency | 4 |
| 70 | PIN data required | 2 |
| 74 | Different value than that used for PIN encription errors | 3 |
| 75 | PIN-entry tries exeeded | 4 |
| 76 | Uneable to match reversal request to an original messsage | 2 |
| 78 | Blocked, new cardholder not activated or card is temporarily blocked | 4 |
| 79 | Reversed (by switch) | 2 |
| 81 | Cryptographic error found in PIN | 4 |
| 82 | PIN authenticaton interrupted | 4 |
| 85 | Approved | 3 |
| 86 | Cannot verify PIN | — |
| 91 | Time out / System inoperative | 2 |
| 92 | Financial institution or intermediate network facility cannot be found for routing (receiving institution ID invalid) | 2 |
| 93 | Transaction can not be completed, violation of law | 4 |
| 92 | Duplicated transmition for transaction | 2 |
| 96 | System malfuntion | 4 |
| 1A | Additional customer authentication required | 2 |
| 6P | Verification data failed | 3 |
| N0 | Issuer forzed authorization via STIP (VIP) | 3 |
| N7 | Decline for CVV2 failure | 4 |
| N8 | Transaction amount exceeds pre authorized approval amount | 3 |
| Q1 | Card authentication failed or PIN authentication interrumpted | 4 |
| R0 | Stop payment order | 4 |
| R1 | Stop all future payments | 1 |
| R2 | Transaction does not qualify for Visa PIN | 1 |
| R3 | Stop all payments | 4 |
| Z3 | Uneable to go online; offline-declined | 1 |

> **⚠ Cuidado al leer esta tabla.** En el PDF original la columna "Categoría" está impresa como una lista suelta al costado, separada de la tabla de códigos. El emparejamiento código→categoría de arriba respeta el orden en que aparecen ambas listas, pero como el PDF trae **61 códigos y 61 categorías en dos bloques independientes**, y además repite el código `92` en dos filas distintas, conviene validar el mapeo con Fiserv antes de usarlo para lógica de reintentos.

**Dónde llega el código ISO:**

- **API SOAP:** `ProcessorAssociationResponseCode`, con la descripción en `ProcessorAssociationResponseMessage`.
- **API REST:** `AssociationResponseCode`, con la descripción en `AssociationResponseMessage`.

\* Ver el aviso de tarifas del comunicado original.

## Tabla de reintentos MASTERCARD (adjunto recuperado)

*Fuente: `TABLA_REINTENTOS_MASTERCARD_062024.pdf` — adjunto enlazado desde `Penalizacion por Reintentos Visa - Master.pdf` (https://destinab.ly/storage/fiserv/TABLA_REINTENTOS_MASTERCARD_062024.pdf). El archivo no estaba en la carpeta; se recuperó desde el enlace embebido en el PDF.*

Cada transacción rechazada por los emisores tendrá relacionado al código ISO un **Merchant Advice Code (MAC)**, el cual informará la cantidad de reintentos permitidos en cada caso. En caso de superar los reintentos informados por el MAC, se procederá al cobro de **USD 0,50\*** por transacción.

> **IMPORTANTE.** En caso de no recibir en la transacción el `MerchantAdviceCodeIndicator`, la cantidad de reintentos permitidos será de **7 por día con un máximo de 35 en 30 días**.

### Merchant Advice Code (MAC) Mastercard

| MAC | Descripción | Reintentos permitidos |
| --- | --- | --- |
| 01 | Nueva Información de Cuenta Disponible | 7 x día con un máx. de 35 en 30 días |
| 02 | No se puede aprobar en este momento | 7 x día con un máx. de 35 en 30 días |
| 03 | No Lo Intente De Nuevo | No reintentar |
| 04 | No se cumplieron los requisitos del token para este tipo de token | 7 x día con un máx. de 35 en 30 días |
| 05 | Valor negociado no aprobado | 7 x día con un máx. de 35 en 30 días |
| 21 | Cancelación de Pago (sólo para uso de Mastercard) | No reintentar |
| 22 | El comercio no califica para el código de producto | 7 x día con un máx. de 35 en 30 días |
| 24 | Reintentar después de 1 hora (uso de Mastercard solamente) | Reintentar después de 1 hora |
| 25 | Reintentar después de 24 horas (uso de Mastercard solamente) | Reintentar después de 24 horas |
| 26 | Reintentar después de 2 días (uso de Mastercard solamente) | Reintentar después de 2 días |
| 27 | Reintentar después de 4 días (uso de Mastercard solamente) | Reintentar después de 4 días |
| 28 | Reintentar después de 6 días (uso de Mastercard solamente) | Reintentar después de 6 días |
| 29 | Reintentar después de 8 días (uso de Mastercard solamente) | Reintentar después de 8 días |
| 30 | Reintentar después de 10 días (uso de Mastercard solamente) | Reintentar después de 10 días |

**Dónde llega el MAC:**

- **API SOAP:** `MerchantAdviceCodeIndicator`, con la descripción en `TransactionDeclineReason`.
- **API REST:** `MerchantAdviceCodeIndicator`, con la descripción en `declineReasonCode`.

### Doble penalidad

En caso de superar los reintentos informados por el MAC se cobra USD 0,50\* por transacción por incumplimiento del mandato del MAC. **En paralelo**, de corresponder, se aplica la penalidad general por reintentos indebidos, por otros USD 0,50\* por transacción.

Ejemplos del documento original:

- El comercio recibe un rechazo con MAC 3. Si reintenta: penalidad por incumplir el MAC, porque el MAC 3 indica no reintentar (USD 0,50).
- El comercio recibe un rechazo con MAC 26. Si reintenta antes de los 2 días: penalidad por incumplir el MAC (USD 0,50).
- El comercio recibe un rechazo con MAC 26. Si reintenta antes de los 2 días, a partir del reintento 8 recibirá: penalidad por incumplir el MAC (USD 0,50) **más** penalidad por superar el número general de reintentos indebidos (USD 0,50).

### Respuestas ISO Mastercard

| ISO CODE | Descripción |
| --- | --- |
| 00 | Approved |
| 01 | Contact card issuer |
| 03 | Invalid merchant |
| 04 | Hold card |
| 05 | Do not honor |
| 08 | Approved with identification |
| 10 | Partial approval |
| 12 | Invalid transaction |
| 13 | Invalid amount |
| 14 | Invalid card number |
| 15 | Invalid issuer |
| 30 | Formar error |
| 41 | Lost card, Hold |
| 43 | Stolen card, Hold |
| 51 | insufficient funds |
| 54 | Expired card |
| 55 | Invalid PIN |
| 57 | Transaction no permitted to issuer |
| 58 | Transaction not permited |
| 62 | Resctricted card |
| 63 | Security violation |
| 65 | Authentification needed |
| 70 | Contact card issuer |
| 71 | PIN not changed |
| 75 | PIN tries exceeded |
| 76 | Invalid transaction. Account non existent |
| 77 | Invalid transaction. Account non existent |
| 78 | Invalid transaction. Account non existent |
| 79 | Post authorization days complete |
| 81 | Domestic debit transaction not allowed |
| 82 | Validate card address |
| 83 | Fraud / Security (Mastercard use only) |
| 84 | Invalid post Authorisations, days past |
| 85 | Approved |
| 86 | PIN Validation not possible |
| 87 | Pourchase amount only, no cash back allowed |
| 88 | Cryptographic failure |
| 89 | Unacceptable PIN - Transaction declined - Retry |
| 91 | Authoritation System or Issuer System inoperative |
| 92 | Unable to route transaction |
| 94 | Duplicate transmition detected |
| 96 | System error |

**Dónde llega el código ISO:** igual que en Visa — `ProcessorAssociationResponseCode` / `ProcessorAssociationResponseMessage` en SOAP, `AssociationResponseCode` / `AssociationResponseMessage` en REST.

\* Ver el aviso de tarifas del comunicado original.


---

# Parte 9 — Buenas prácticas y seguridad

## 14. Buenas prácticas y anotaciones técnicas

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §14*

1. Asegúrate de almacenar en un lugar seguro tus credenciales (API Key y API Secret). Es muy importante conservar estos datos protegidos y que no sean accesibles desde un navegador.

   Sugerencia:
   Puedes guardar estas credenciales en una base de datos definiendo un único usuario y que solamente sea accesible desde host autorizados; también puedes crear un archivo de configuración en un directorio NO PÚBLICO, de esta manera únicamente tu sabrás la ubicación del archivo y no tendrán acceso a personas no autorizadas.

2. En caso de utilizar código JavaScript en tu sitio, evita cualquier tipo de log en un entorno productivo, ya que imprimir mensajes pueden servir de guía a un agente no autorizado para modificar de manera local el archivo JavaScript.

3. Evita almacenar cualquier dato sensible de tus usuarios o credenciales en variables de JavaScript.

4. Cualquier proceso que involucre la consulta de información como credenciales o datos sensibles deberá realizarse en un lenguaje ejecutado del lado del servidor como PHP o ASP.NET. Jamás consultes tu base de datos directamente desde código JavaScript.

   Sugerencia
   Si en realidad necesitas realizar una consulta a una base de datos, puedes crear un archivo auxiliar PHP o ASP.NET y enviar una petición Ajax desde JavaScript. Gracias a que este archivo es ejecutado por el servidor, puedes construir en él, la conexión con la BD y de esta forma devolver el resultado de la consulta a tu archivo JavaScript original. No olvides limitar la conexión de tu archivo auxiliar para que solo permita peticiones desde el host donde se encuentra el mismo sitio web.

5. Como medida de seguridad adicional, evita permitir el listado de directorios desde tu hosting. Muchos proveedores de hosting tienen esta opción habilitada de manera predeterminada. De esta forma evitas la descarga del código fuente de tus archivos.

6. Para reducir las transacciones no reconocidas o fraudulentas se sugiere utilizar siempre la autenticación con 3D Secure.

7. Si el proceso de tu sitio web lo permite, se sugiere autenticar y tener un registro de todos los usuarios que lo utilizan.

8. Para evitar transacciones duplicadas, es importante incluir el parámetro “orderId” definido dentro del objeto “Order” para las transacciones primarias.


---

# Parte 10 — Tarjetas y datos de prueba

Tarjetas de test para integración estándar, para 3DS y para simular rechazos por importe.

## Apéndice IV. Tarjetas de Test para integraciones estándar

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §Apéndice IV*

Las siguientes tarjetas pueden ser utilizadas en el ambiente de test de nuestro gateway:

**Argentina**

| Tarjeta | Exp | cvv | PaymentMethod |
| --- | --- | --- | --- |
| 5165850000000008 | dic-29 | 123 | MASTERCARD |
| 4704550000000005 | dic-29 | 123 | VISA |
| 5895620000000002 | oct-29 | 123 | NARANJA |
| 376411234531007 | dic-23 | 1234 | AMEX |
| 3528000000000015 | dic-23 | 123 | JCB |
| 5896570000000008 | dic-29 | 123 | CABAL_ARGENTINA |
| 5011050000000001 | dic-29 | 123 | ARGENCARD |
| 5427020000000002 | dic-29 | 123 | MASTERCARD |
| 6271700000000000 | dic-23 | 123 | KADICARD |
| 504408000000000017 | dic-23 | 123 | FAVACARD |
| 5045200000000010 | dic-23 | 123 | CREDIMAS |
| 5043631200000001 | dic-23 | 123 | NEVADA |
| 5046560000000016 | dic-23 | 123 | PATAGONIA_365 |
| 5046390000000018 | dic-23 | 123 | SOL |
| 6391300085755808 | dic-23 | 123 | CLUB_LA_NACION |
| 5049100100000000 | dic-23 | 123 | PYME_NACION |
| 3086250011038020004 | dic-23 | 123 | CLARIN_365 |
| 4870170040000002 | dic-23 | 123 | NATIVA |
| 6034160000000000 | dic-23 | 123 | CONSUMAX |
| 4210240000000000 | dic-23 | 123 | MIRA |
| 6032880000000004 | dic-23 | 123 | CREDI_GUIA |
| 6063010000000018 | dic-23 | 123 | GRUPAR |
| 5888000000000014 | dic-23 | 123 | TUYA |
| 5045700000000019 | dic-23 | 123 | QIDA |
| 5047770000000002 | dic-23 | 123 | ELEBAR |
| 5045690000000004 | dic-23 | 123 | AUTOMATICA |
| 4123220010000014 | dic-27 | 415 | VISA_DEBITO |
| 501063999000007007 | dic-30 | 97 | MAESTRO |

**Uruguay**

| Tarjeta | Exp | cvv | Marca |
| --- | --- | --- | --- |
| 4103770000000006 | dic-29 | s/cvv | VISA URUGUAY CRÉDITO |
| 4213000000000005 | dic-29 | s/cvv | VISA URUGUAY DÉBITO (V6) |
| 4345590000000006 | dic-29 | s/cvv | VISA INTERNACIONAL DÉBITO (VD) |
| 4147960000000001 | dic-29 | s/cvv | VISA INTERNACIONAL CRÉDITO (VI) |
| 5101980000000000 | dic-29 | s/cvv | MASTERCARD CRÉDITO URUGUAY (PM NO PROCESADO) |
| 5599260000000006 | dic-29 | s/cvv | MASTERCARD PREPAGA URUGUAY (Afiliados ICA 2189) |

Bloque original de las tablas de tarjetas (Argentina y Uruguay), tal como aparece en el documento:

```
                                           Argentina
        Tarjeta              Exp       cvv                     PaymentMethod
  5165850000000008          dic-29     123                      MASTERCARD
  4704550000000005          dic-29     123                           VISA
  5895620000000002          oct-29     123                         NARANJA
   376411234531007          dic-23    1234                           AMEX
  3528000000000015          dic-23     123                            JCB
  5896570000000008          dic-29     123                   CABAL_ARGENTINA
  5011050000000001          dic-29     123                       ARGENCARD
  5427020000000002          dic-29     123                      MASTERCARD
  6271700000000000          dic-23     123                         KADICARD
 504408000000000017         dic-23     123                        FAVACARD
  5045200000000010          dic-23     123                        CREDIMAS
  5043631200000001          dic-23     123                          NEVADA
  5046560000000016          dic-23     123                     PATAGONIA_365
  5046390000000018          dic-23     123                            SOL
  6391300085755808          dic-23     123                    CLUB_LA_NACION
  5049100100000000          dic-23     123                      PYME_NACION
 3086250011038020004        dic-23     123                        CLARIN_365
  4870170040000002          dic-23     123                          NATIVA
  6034160000000000          dic-23     123                        CONSUMAX
  4210240000000000          dic-23     123                           MIRA
  6032880000000004          dic-23     123                       CREDI_GUIA
  6063010000000018          dic-23     123                          GRUPAR
  5888000000000014          dic-23     123                           TUYA
  5045700000000019          dic-23     123                           QIDA
  5047770000000002          dic-23     123                          ELEBAR
  5045690000000004          dic-23     123                       AUTOMATICA
  4123220010000014          dic-27     415                       VISA_DEBITO
 501063999000007007         dic-30     97                          MAESTRO
                                              Uruguay
        Tarjeta              Exp       cvv                       Marca
   4103770000000006         dic-29    s/cvv             VISA URUGUAY CRÉDITO
   4213000000000005         dic-29    s/cvv            VISA URUGUAY DÉBITO (V6)
   4345590000000006         dic-29    s/cvv         VISA INTERNACIONAL DÉBITO (VD)
   4147960000000001         dic-29    s/cvv        VISA INTERNACIONAL CRÉDITO (VI)
                                                 MASTERCARD CRÉDITO URUGUAY (PM NO
   5101980000000000         dic-29    s/cvv
                                                             PROCESADO)
                                                MASTERCARD PREPAGA URUGUAY (Afiliados
   5599260000000006         dic-29    s/cvv
                                                               ICA 2189)
```

Se pueden simular rechazos de emisores en función del importe:

| Amount | ResponseCode | Response |
| --- | --- | --- |
| 1000.00 | 0 | |
| 1000.01 | unanswered | N: |
| 1001.00 | 1 | N:01:Refer to card issuer |
| 1002.00 | 2 | N:02:Refer to special conditions for card issuer |
| 1003.00 | 3 | N:03:Invalid merchant |
| 1005.00 | 5 | N:05:Do not honour |
| 1007.00 | 7 | N:07:Pick-up card, special condition |
| 1013.00 | 13 | N:13:Invalid amount |
| 1014.00 | 14 | N:14:Invalid card number (no such number) |
| 1031.00 | 31 | N:31:Unknown Response Code |
| 1045.00 | 45 | N:45:The card can't operate with installments |
| 1046.00 | 46 | N:46:Card expired |
| 1051.00 | 51 | N:51:Not sufficient fund |
| 1054.00 | 54 | N:54:Expired card |
| 1056.00 | 56 | N:56:No card record |
| 1061.00 | 61 | N:61:Exceeds withdrawal amount limit |
| 1076.00 | 76 | N:76:Request phone authorization, in case if the transaction is approved, load the retrieve code and leave the operation offline |
| 1091.00 | 91 | N:91:Issuer or switch is inoperative |

## Apéndice V. Tarjetas de test para 3DS

*Fuente: Guía de Integración API Rest Argentina 2026 (Fiserv IPG, v2.0 jun-2025, ARG & URY) — §Apéndice V*

El propósito de las tarjetas de prueba 3DS es simular respuestas de la AUTENTICACIÓN, es decir, no garantizan automáticamente la AUTORIZACIÓN aprobada.

Las tarjetas de prueba solo deben usarse para el ESCENARIO DE AUTENTICACIÓN / CASO DE PRUEBA que admiten; el uso indebido de la tarjeta para cualquier otra respuesta de autenticación no proporcionará el resultado correcto. La descripción sugiere un escenario aplicable, por ejemplo, la tarjeta de prueba "Frictionless Y" puede proporcionar el valor de autenticación transStatus=Y y el valor ECI correspondiente (02 o 05).

- Fecha de vencimiento de todas las tarjetas = 12-29
- cvv = 123

**Authentication Transaction Status**

| Value | Description |
| --- | --- |
| Y | Fully Authenticated |
| N | Not Authenticated, cardholder not enrolled |
| A | Attempted Authentication |
| R | Rejected Authentication |
| U | Unable to Authenticate, ACS Not responding/Invalid 3DS Values received |

**Frictionless Flow**

| Escenario | 3DS Response Code | 3DS Transaction Status | Tarjeta |
| --- | --- | --- | --- |
| Frictionless - Fully Authenticated | 1 | Y | 4147463011110083<br>5239290700000028 |
| Frictionless - Not Authenticated | 3 | N | 4147463011110091<br>5239290700000036 |
| Frictionless - Attempted Authentication | 4 | A | 4147463011110117<br>5239290700000044 |
| Frictionless - Rejected Authentication | 3 | R | 4147463011110042<br>4016360000000085<br>5188340000000052 |
| Frictionless - Unable to authenticate | 6 | U | 4147463011110067<br>4147463011110125<br>5239290700000069 |

Bloque original de la tabla, tal como aparece en el documento (los números de tarjeta figuran agrupados en bloques de 8 dígitos):

```
                                         Frictionless Flow
                                                                3DS
                                          3DS Response
               Escenario                                     Transaction           Tarjeta
                                              Code
                                                               Status
                                                                            41474630 11110083
    Frictionless - Fully Authenticated          1                Y
                                                                            52392907 00000028
                                                                            41474630 11110091
    Frictionless - Not Authenticated            3                N
                                                                            52392907 00000036
        Frictionless - Attempted                                            41474630 11110117
                                                4                A
              Authentication                                                52392907 00000044
                                                                            41474630 11110042
         Frictionless - Rejected
                                                3                R          40163600 00000085
             Authentication
                                                                            51883400 00000052
                                                                            41474630 11110067
 Frictionless - Unable to authenticate          6                U          41474630 11110125
                                                                            52392907 00000069
```

**Frictionless Flow + 3DSMethod**

| Escenario | 3DS Response Code | 3DS Transaction Status | Tarjeta |
| --- | --- | --- | --- |
| Frictionless - Fully Authenticated | 1 | Y | 4099000000001978<br>5204740000002711 |
| Frictionless - Not Authenticated | 3 | N | 4099000000001986<br>5426064000425117 |
| Frictionless - Attempted Authentication | 4 | A | 4149011500000519<br>5426064000425208 |
| Frictionless - Rejected Authentication | 3 | R | 4265880000000031<br>5204740000002778 |
| Frictionless - Unable to authenticate | 6 | U | 4265880000000080<br>5426064000425216 |

Bloque original de la tabla, tal como aparece en el documento:

```
                            Frictionless Flow + 3DSMethod
                                                             3DS
                                        3DS Response
             Escenario                                    Transaction        Tarjeta
                                            Code
                                                            Status
                                                                        40990000 00001978
 Frictionless - Fully Authenticated            1               Y
                                                                        52047400 00002711
                                                                        40990000 00001986
  Frictionless - Not Authenticated             3              N
                                                                        54260640 00425117
      Frictionless - Attempted                                          41490115 00000519
                                               4               A
            Authentication                                              54260640 00425208
       Frictionless - Rejected                                          42658800 00000031
                                               3              R
           Authentication                                               52047400 00002778
                                                                        42658800 00000080
Frictionless - Unable to authenticate          6              U
                                                                        54260640 00425216
```

**Challenge Flow**

| Escenario | 3DS Response Code | 3DS Transaction Status | Tarjeta |
| --- | --- | --- | --- |
| Challenge - R | 3 | R | 4147463011110034<br>5239290700000010 |
| Challenge - configurable response | 1 | Y | 4147463011110059<br>5239290700000002 |
| Challenge - configurable response | 4 | A | 4147463011110059<br>5239290700000002 |
| Challenge - configurable response | 3 | R/N | 4147463011110059<br>5239290700000002 |
| Challenge - configurable response | 6 | U | 4147463011110059<br>5239290700000002 |

Bloque original de la tabla, tal como aparece en el documento (la fila "Challenge - configurable response" abarca los cuatro códigos de respuesta 1/Y, 4/A, 3/R-N y 6/U con el mismo par de tarjetas):

```
                                        Challenge Flow
                                                            3DS
         Escenario               3DS Response Code       Transaction         Tarjeta
                                                           Status
                                                                        41474630 11110034
       Challenge - R                     3                   R
                                                                        52392907 00000010

                                         1                   Y


                                         4                   A
 Challenge - configurable                                               41474630 11110059
        response                                                        52392907 00000002
                                         3                  R/N

                                         6                   U
```

**Challenge Flow + 3DSMethod**

| Escenario | 3DS Response Code | 3DS Transaction Status | Tarjeta |
| --- | --- | --- | --- |
| Challenge - R | 3 | R | 4147463011110034<br>5204740000002760 |
| Challenge - configurable response | 1 | Y | 4265880000000064<br>5204740000002745 |
| Challenge - configurable response | 4 | A | 4265880000000064<br>5204740000002745 |
| Challenge - configurable response | 3 | R/N | 4265880000000064<br>5204740000002745 |
| Challenge - configurable response | 6 | U | 4265880000000064<br>5204740000002745 |

Bloque original de la tabla, tal como aparece en el documento (la fila "Challenge - configurable response" abarca los cuatro códigos de respuesta 1/Y, 4/A, 3/R-N y 6/U con el mismo par de tarjetas):

```
                             Challenge Flow + 3DSMethod
                                                            3DS
         Escenario               3DS Response Code       Transaction         Tarjeta
                                                           Status
                                                                        41474630 11110034
       Challenge - R                     3                   R
                                                                        52047400 00002760

                                         1                   Y


                                         4                   A
 Challenge - configurable                                               42658800 00000064
        response                                                        52047400 00002745
                                         3                  R/N

                                         6                   U
```

## Tarjetas de prueba (Credit cards for test)

*Fuente: Credit cards for test.pdf*

These are the test cards that you can use in the E-Posnet testing environment:

| Card | ExpDate | Security Code | PaymentMethod |
| --- | --- | --- | --- |
| 5165850000000008 | dic-29 | 123 | MASTERCARD |
| 4704550000000005 | dic-29 | 123 | VISA |
| 5895620000000002 | oct-29 | 123 | NARANJA |
| 376411234531007 | dic-23 | 1234 | AMEX |
| 3528000000000015 | dic-29 | 123 | JCB |
| 5896570000000008 | dic-29 | 123 | CABAL_ARGENTINA |
| 6271700000000000 | dic-29 | 123 | KADICARD |
| 504408000000000017 | dic-29 | 123 | FAVACARD |
| 5045200000000010 | dic-29 | 123 | CREDIMAS |
| 5043631200000001 | dic-29 | 123 | NEVADA |
| 5046560000000016 | dic-29 | 123 | PATAGONIA_365 |
| 5046390000000018 | dic-29 | 123 | SOL |
| 6391300085755808 | dic-29 | 123 | CLUB_LA_NACION |
| 5049100100000000 | dic-29 | 123 | PYME_NACION |
| 3086250011038020004 | dic-29 | 123 | CLARIN_365 |
| 4870170040000002 | dic-29 | 123 | NATIVA |
| 6034160000000000 | dic-29 | 123 | CONSUMAX |
| 4210240000000000 | dic-29 | 123 | MIRA |
| 6032880000000004 | dic-29 | 123 | CREDI_GUIA |
| 6063010000000018 | dic-29 | 123 | GRUPAR |
| 5888000000000014 | dic-29 | 123 | TUYA |
| 5045700000000019 | dic-29 | 123 | QIDA |
| 5047770000000002 | dic-29 | 123 | ELEBAR |
| 5045690000000004 | dic-29 | 123 | AUTOMATICA |
| 4123220010000014 | dic-27 | 415 | VISA_DEBITO |
| 501063999000007007 | dic-30 | 97 | MAESTRO |

Issuer rejections can be simulated depending on the amount deposited:

| Amount | Response Code | Response |
| --- | --- | --- |
| 1000.00 | 0 | |
| 1000.01 | unanswered | N: |
| 1001.00 | 1 | N:01:Refer to card issuer |
| 1002.00 | 2 | N:02:Refer to special conditions for card issuer |
| 1003.00 | 3 | N:03:Invalid merchant |
| 1005.00 | 5 | N:05:Do not honour |
| 1007.00 | 7 | N:07:Pick-up card, special condition |
| 1013.00 | 13 | N:13:Invalid amount |
| 1014.00 | 14 | N:14:Invalid card number (no such number) |
| 1031.00 | 31 | N:31:Unknown Response Code |
| 1045.00 | 45 | N:45:The card can't operate with installments |
| 1046.00 | 46 | N:46:Card expired |
| 1051.00 | 51 | N:51:Not sufficient fund |
| 1054.00 | 54 | N:54:Expired card |
| 1056.00 | 56 | N:56:No card record |
| 1061.00 | 61 | N:61:Exceeds withdrawal amount limit |
| 1076.00 | 76 | N:76:Request phone authorization, in case if the transaction is approved, load the retrieve code and leave the operation offline |
| 1091.00 | 91 | N:91:Issuer or switch is inoperative |

| Tarjeta | Security Code | Vencimiento | Marca |
| --- | --- | --- | --- |
| 4103770000000006 | S/CVV | dic-29 | Visa Uruguay Crédito |
| 4213000000000005 | S/CVV | dic-29 | Visa Uruguay Débito (V6) |
| 4345590000000006 | S/CVV | dic-29 | Visa Internacional Débito (VD) |
| 4147960000000001 | S/CVV | dic-29 | Visa Internacional Crédito (VI) |
| 5101980000000000 | S/CVV | dic-29 | Mastercard Credito Uruguay (PM No Procesado) |
| 5599260000000006 | S/CVV | dic-29 | Mastercard Prepaga Uruguay (Afiliados ICA 2189) |

| 3DS response 3 | ExpDate | Security Code |
| --- | --- | --- |
| 5188340000000052 | dic-29 | 123 |
| 4016360000000085 | dic-29 | 123 |


---

# Parte 11 — Homologación

Casos de prueba que Fiserv exige ejecutar y registrar antes de pasar a producción.

## Checklist de homologación — 3DS FULL / API / Token (PXSOL)

*Fuente: Homologación - 3ds FULL API token PXSOL.docx*

Estimados,

Con la finalidad de reducir los errores en producción es necesario que realicen un conjunto de pruebas desde sus sistemas ya integrados en su totalidad con el Gateway para que de nuestro lado evaluemos mediante Logs las request realizadas y nos aseguremos que todo se está enviando o utilizando de manera correcta.

Una vez verificados los mismos, en el plazo de 3 días Hábiles estaremos comunicándoles el resultado de la misma.

En la Homologación se estarían esperando los siguientes casos de prueba

(los casos remarcados en rojo son de implementación obligatoria):

> **Nota:** el documento original marcaba en rojo los casos obligatorios; el color no se preserva en esta conversión.

StoreID (Numero de la Tienda):

| Caso de prueba | Fecha | OrderID |
| --- | --- | --- |
| realizar una transacción de tipo sale en 1 pago | | |
| realizar una transacción de tipo sale en 1 pago con DOLAR | | |
| realizar una transacción de tipo sale con ZEROAUTH | | |
| realizar una transacción de tipo sale en cuotas con TOKEN GW ( UTLIZAR TARJETA 5165850000000008 cvv 123 12/29) ( TIENDA 5926072902) | | |
| realizar una transacción de tipo sale en cuotas con TOKEN MTRG ( UTLIZAR TARJETA 4622943127032366 cvv 123 12/29) ( TIENDA 5926072901) | | |
| INQUIRY ORDER | | |
| DYNAMIC MERCHANT NAME | | |
| realizar una transacción de tipo void (Anulación) | | |
| realizar una transacción de tipo return por el monto total (Devolución) | | |
| realizar una transacción de tipo return por el monto parcial (Devolución) | | |

### 3DS Frictionless

| 3DS Frictionless | Tarjetas para pruebas | Month | Year | CVV | Fecha | OrderID |
| --- | --- | --- | --- | --- | --- | --- |
| Frictionless Authenticated | 4147463011110083 | 12 | 29 | 123 | | |
| Frictionless Not Authenticated | 4147463011110091 | 12 | 29 | 123 | | |
| Frictionless Attempted Authentication | 4147463011110117 | 12 | 29 | 123 | | |
| Frictionless Rejected Authentication | 4147463011110042 | 12 | 29 | 123 | | |
| Frictionless Unable to Authenticate | 4147463011110067 | 12 | 29 | 123 | | |

### 3DS Method

| 3DS Method | Tarjetas para pruebas | Month | Year | CVV | Fecha | OrderID |
| --- | --- | --- | --- | --- | --- | --- |
| 3DSMethod Authenticated | 4099000000001978 | 12 | 29 | 123 | | |
| 3DSMethod Not Authenticated | 4265880000000015 | 12 | 29 | 123 | | |
| 3DSMethod Attempted Authentication | 4149011500000519 | 12 | 29 | 123 | | |
| 3DSMethod Rejected Authentication | 4016360000000085 | 12 | 29 | 123 | | |
| 3DSMethod Unable to Authenticate | 4265880000000080 | 12 | 29 | 123 | | |

### 3DS Challenge

| 3DS Challenge | 3DS Response Code | Tarjetas para pruebas | Month | Year | CVV | Fecha | OrderID |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Challenge - R | 3 | 4147463011110034 | 12 | 29 | 123 | | |
| Challenge - configurable / response | 1 | 4147463011110059 | 12 | 29 | 123 | | |
| Challenge - configurable / response | 4 | 4147463011110059 | 12 | 29 | 123 | | |
| Challenge - configurable / response | 3 | 4147463011110059 | 12 | 29 | 123 | | |
| Challenge - configurable / response | 6 | 4147463011110059 | 12 | 29 | 123 | | |

### 3DS Challenge + Method

| 3DS Challenge + Method | 3DS Response Code | Tarjetas para pruebas | Month | Year | CVV | Fecha | OrderID |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Challenge - R | 3 | 4149011500000535 | 12 | 29 | 123 | | |
| Challenge - configurable / response | 1 | 4265880000000064 | 12 | 29 | 123 | | |
| Challenge - configurable / response | 4 | 4265880000000064 | 12 | 29 | 123 | | |
| Challenge - configurable / response | 3 | 4265880000000064 | 12 | 29 | 123 | | |
| Challenge - configurable / response | 6 | 4265880000000064 | 12 | 29 | 123 | | |

### 3DS

| 3DS | Tarjetas para pruebas | Month | Year | CVV | Fecha | OrderID |
| --- | --- | --- | --- | --- | --- | --- |
| DataOnly | 5239290700000028 | 12 | 29 | 123 | | |

### Stores a usar y dónde está documentado cada caso

Los dos stores de Argentina no son intercambiables: el checklist asigna uno a cada tipo de token.

| Caso del checklist | Store | Dónde está explicado en este documento |
|---|---|---|
| Sale en 1 pago | `5926072901` / `5926072902` | §7 Transacciones básicas |
| Sale en 1 pago con DÓLAR | idem | §7 — cambiar `transactionAmount.currency` |
| Sale con ZEROAUTH | idem | Parte 3 — Zero Auth (`total: "0"`) |
| Sale en cuotas con **TOKEN GW** — tarjeta `5165850000000008` | **`5926072902`** | §9.1 Tokenización IPG + `order.installmentOptions` |
| Sale en cuotas con **TOKEN MTRG** — tarjeta `4622943127032366` | **`5926072901`** | Parte 4 — Network Token (MTRG) + §9.2 passthrough |
| INQUIRY ORDER | idem | §7.3 Consulta del estado de la transacción |
| DYNAMIC MERCHANT NAME | idem | `SoftDescriptor/dinamycMerchantName` (§7.2 y Apéndice III) |
| Void (anulación) | idem | §7.2 — `VoidTransaction` / `VoidPreAuthTransactions` |
| Return total y parcial | idem | §7.2 — `ReturnTransaction` |
| 3DS Frictionless / Method / Challenge | idem | §10.1 (proveedor propio) o §10.2 (passthrough) |
| DataOnly — tarjeta `5239290700000028` | idem | §10.1.6 / §10.2.2 — `messageCategory: "80"` |

Las credenciales de estos stores están en la Parte 1.

### ⚠ Las tarjetas del checklist no coinciden con el Apéndice V de la guía

Al cruzar las 16 tarjetas 3DS del checklist contra el Apéndice V ("Tarjetas de test para 3DS"), **3 no coinciden**. Como usar la tarjeta equivocada devuelve otro `transStatus` y el caso se da por fallido, conviene resolver esto antes de empezar:

| Escenario del checklist | Tarjeta que pide el checklist | Lo que dice el Apéndice V | Situación |
|---|---|---|---|
| 3DSMethod **Not** Authenticated | `4265880000000015` | `4099000000001986` (Frictionless + 3DSMethod, código 3 / N) | La tarjeta del checklist **no figura en el Apéndice V** |
| 3DSMethod **Rejected** Authentication | `4016360000000085` | `4265880000000031` (Frictionless + 3DSMethod, código 3 / R) | `4016360000000085` sí existe, pero el Apéndice V la ubica en el flujo Frictionless **sin** 3DSMethod |
| Challenge + Method — **Challenge - R** | `4149011500000535` | `4147463011110034` (Challenge Flow + 3DSMethod, código 3 / R) | La tarjeta del checklist **no figura en el Apéndice V** |

Las otras 13 coinciden exactamente. Criterio sugerido: usar las del checklist, porque es el documento contra el que Fiserv evalúa los logs, y pedirles por escrito que confirmen las tres discrepancias.

Nota aparte: la tarjeta de DataOnly del checklist (`5239290700000028`) figura en el Apéndice V como la Mastercard de "Frictionless - Fully Authenticated" (código 1 / Y). Es coherente — Data Only es exclusivo de Mastercard y se activa con `messageCategory: "80"`, no con una tarjeta distinta.

Atentamente,

Equipo Soporte IPG - Homologación

soporte.latam@softwareexpress.com.br
<!-- fin del texto original de Fiserv -->

### Verificado en vivo contra CERT (2026-08-06)

Todo lo de esta subsección se comprobó ejecutando los casos contra
`https://cert.api.firstdata.com/gateway/v2` con las credenciales de PXSOL, no
sale de la lectura del doc. El harness que lo reproduce es
`./fiserv_homologacion.py` (evidencia en `fiserv_homologacion_logs/<corrida>/`).

**Los updates de 3DS son `PATCH`, no `POST`.** El doc lo dice en prosa
("realizando una operación PATCH", §10.1.4.a y §10.1.5.d) pero ningún ejemplo
muestra el verbo. Con `POST /payments/{id}` el gateway responde
`INVALID_INPUT` / `{"field":"requestType","message":"Request type missing."}`,
porque en POST el discriminador es `requestType` y en PATCH es
`authenticationType`. Aplica tanto al update de `methodNotificationStatus` como
al de `acsResponse.cRes`.

**El paso 3DSMethod se puede ejecutar de verdad sin browser.** El `methodForm`
que devuelve el gateway es un form que postea `3DSMethodData` y
`threeDSMethodData` a `https://3ds-acs.test.modirum.com/mdpayacs/3ds-method`.
Posteándolo server-side, el ACS responde con el form de notificación que apunta
al `methodNotificationURL` declarado — o sea que la notificación se emite igual
que con el iframe del browser, y recién entonces corresponde mandar el `PATCH`
con `methodNotificationStatus: "RECEIVED"`. (Un `PATCH` con `RECEIVED` a secas
también completa la autenticación, pero declara algo que no pasó.)

**El ACS de test (Modirum) tiene un simulador con el que se elige el resultado
del challenge.** Eso es lo que significan las filas "Challenge - configurable /
response 1 / 4 / 3 / 6": es la misma tarjeta y se aprieta un botón distinto.
Al postear el `cReq` a `acsURL`, el ACS devuelve una pantalla con cinco botones
`name="result"`; el resultado final medido es:

| Botón del ACS | `result` | `responseCode3dSecure` | Estado de la transacción |
|---|---|---|---|
| Yes | `y` | **1** | APPROVED |
| Attempt | `a` | **4** | APPROVED |
| No | `n` | **3** (reason 1) | VALIDATION_FAILED / 50716 |
| Rejected | `r` | **3** (reason 19) | VALIDATION_FAILED / 50716 |
| Unavailable | `u` | **6** (reason 22) | APPROVED |

Las tarjetas "Challenge - R" (`4147463011110034` y `4149011500000535`) no
muestran el simulador: el ACS devuelve el `cRes` directo con `transStatus: N`,
que da código 3. Como el ACS postea el `cRes` a `termURL`, todo el flujo se
puede correr por HTTP sin browser apuntando `termURL` a `localhost`.

**`softDescriptor` va dentro de `order`.** A nivel raíz del payload el gateway
responde `No field named 'softDescriptor' exists for class
PaymentCardSaleTransaction`. El nombre del campo interno es
`dynamicMerchantName` (el doc lo escribe `dinamycMerchantName` en §7.2 y en el
Apéndice III; esa grafía no existe en la API).

**Data Only con proveedor propio falla; con proveedor externo funciona.** Con
`authenticationRequest` → `authenticationType: "Secure3DAuthenticationRequest"` +
`messageCategory: "80"` (§10.1.6) el gateway responde `VALIDATION_FAILED`,
`error.code 50655 "Unable to verify card enrollment"` y
`responseCode3dSecure: 8`. Se reprodujo con las dos Mastercard del doc
(`5239290700000028` y `5165850000000008`) y en las dos tiendas AR
(`5926072901` y `5926072902`).

Pero la modalidad **sí está operativa en esas tiendas**: por la vía de proveedor
externo (§10.2.2, bloque `authenticationResult` con `messageCategory: "80"`) la
misma tienda aprueba y devuelve `responseCode3dSecure: A`. Controles que acotan
dónde está el problema:

- la misma MC sin `messageCategory` entra normal al flujo 3DS 2.2 (WAITING + `secure3dMethod`);
- con `messageCategory: "02"` responde `50734 "Invalid NPA Transaction Amount"`, y
  con un valor fuera del enum falla el parseo del JSON: el campo se valida por valor;
- con una **Visa** y `messageCategory: "80"` responde
  `50738 "Invalid Message Category"`: valida también por marca.

> **Ojo con la conclusión fácil.** El código que Fiserv usa para "tienda sin
> habilitar" es `N:-30055 "Not configured for 3DSecure"`, no el `-50655` que
> recibimos, y `-50655` no figura en el PDF de códigos de rechazo. Con lo
> verificado no alcanza para afirmar que falte una habilitación: lo que se puede
> sostener es que falla la modalidad con proveedor propio sobre las tarjetas de
> prueba, y que hay que preguntarle a Fiserv si es enrolamiento de esas PAN en el
> Directory Server de test u otra cosa.
>
> Cerrar el caso del checklist con el flujo §10.2.2 **no** es una opción: esa
> modalidad es para cuando la autenticación la resolvió un proveedor externo, y
> usar el `cavv` de ejemplo de la guía sería fabricar una autenticación.

**`messageCategory` no existe en `Secure3D21AuthenticationRequest`.** Hay que
usar la clase base `Secure3DAuthenticationRequest`, tal como dice §10.1.6. Con
la subclase el gateway responde `No field named 'messageCategory' exists for
class Secure3D21AuthenticationRequest`. Son los dos únicos valores válidos de
`authenticationType` para el request de inicio: cualquier otro rompe la
deserialización polimórfica y devuelve `Request type missing`.

**El caso del checklist "TOKEN MTRG" es el flujo integrado, no el passthrough.**
El checklist da la tarjeta **con CVV**, y eso lo define: el manual de Network
Token sólo tiene dos flujos, *OnTheGo* (se manda el PAN real con CVV y Fiserv le
pide el token a la marca) y *Asíncrono* (se crea un `HostedDataID` y se vende con
él). El passthrough de §9.2 es otro producto, para comercios con TSP propio.
Mandar el PAN del checklist como si fuera un token, sin CVV y con
`order.tokenCryptogram`, **no produce ninguna tokenización**: la respuesta vuelve
con `fundingCardNumber.bin` igual a `paymentCard.bin`. En el flujo correcto sí
hay sustitución: `462294/2366` → `432312/7867`.

**Las cuotas se rechazan por tarjeta no local, no por Network Token.** Con
`order.installmentOptions` el gateway responde `N:-11101:installment not
supported` / `installment only supported for local cards` (código documentado en
el PDF de códigos de rechazo). Se reproduce en los dos flujos, con 6 y con 3
cuotas; con `numberOfInstallments: 1` y sin `installmentOptions` aprueba.

No confundir la causa: en la misma tienda, la Visa `4704550000000005` **también**
se procesa sustituida por Network Token (`470455` → `451718`) y **sí** acepta 6
cuotas. O sea que el Network Token no bloquea cuotas; lo que falla es que el PAN
de prueba de MTRG no resuelve como tarjeta local argentina.

**El criptograma del network token no se valida en CERT** (aplica al passthrough
§9.2, no al flujo MTRG integrado). El doc lo declara obligatorio en cada
transacción, pero una venta sin `order.tokenCryptogram` sale APPROVED igual. Lo
único que se valida es el largo: entre 20 y 256 caracteres. No apoyarse en CERT
para verificar este requisito.

**De las tres discrepancias de tarjetas, sólo una es real.** Corriendo las seis
tarjetas:

| Caso | Tarjeta del checklist | Resultado | Tarjeta del Apéndice V | Resultado |
|---|---|---|---|---|
| 3DSMethod Not Authenticated | `4265880000000015` | código **3** ✅ | `4099000000001986` | código 3 |
| 3DSMethod **Rejected** | `4016360000000085` | código **6** ❌ (reason 8) | `4265880000000031` | código **3** ✅ (reason 11) |
| Challenge+Method - R | `4149011500000535` | código **3** ✅ (reason 11) | `4147463011110034` | código 3 |

O sea: las del checklist sirven salvo en *3DSMethod Rejected*, donde la del
checklist devuelve "Unable" (6) en vez de "Rejected" (3). Para ese caso hay que
usar `4265880000000031` o pedirle a Fiserv que confirme cuál evalúan.

### Preguntas abiertas para Fiserv

1. **Data Only con proveedor propio**: ¿el `-50655` corresponde al enrolamiento
   de las PAN de prueba en el Directory Server de test, o a otra cosa? El código
   no figura en el PDF de códigos de rechazo. ¿Hay una tarjeta de prueba
   específica para este flujo?
2. **TOKEN MTRG en cuotas**: ¿hay un PAN de prueba para MTRG que resuelva como
   tarjeta local argentina, o el caso se homologa en 1 pago?
3. **3DSMethod Rejected**: la tarjeta del checklist (`4016360000000085`) aprueba
   con código 6 y sin ejecutar 3DSMethod. ¿Se da por cumplida así, o se homologa
   con `4265880000000031`?
4. **ZEROAUTH sobre Mastercard**: el manual de Zero Auth pide los parámetros de
   Data Only. ¿Se reenvía cuando se resuelva el punto 1, o se homologa con Visa?
5. **Criptograma de network token** (sólo si se usa passthrough): ¿hay
   criptogramas de test válidos, o CERT acepta cualquiera de largo 20-256?
6. **Credencial almacenada / Card on File**: toda transacción que incluye el
   bloque `storedCredentials` (con `order.installmentOptions.recurringType`)
   es rechazada con *"The merchant is not setup to support the requested
   service"*, en las dos tiendas. La misma venta con token **sin** ese bloque
   devuelve HTTP 200, así que no es la tokenización: parece un servicio no
   habilitado en la cuenta de certificación. ¿Se puede habilitar credencial
   almacenada en 5926072901 / 5926072902? Este caso no está en el checklist,
   pero la recurrencia se necesita para producción.

Notas de método, para no repetir errores al armar estos reclamos:

- El checklist declara un `3DS Response Code` esperado **sólo** en las tablas
  *Challenge* y *Challenge + Method*. Para Frictionless, 3DS Method y DataOnly no
  declara ninguno: comparar contra un valor "esperado" en esas filas es inventar
  un requisito.
- Antes de atribuirle una falla al gateway, buscar el control que la descarta.
  Dos reclamos se cayeron así: el de cuotas (una Visa tokenizada sí acepta
  cuotas) y el de Data Only (el passthrough sí devuelve `A`).
- No afirmar pruebas que no estén en el archivo de evidencia que se adjunta.

### Verificado a través del router de Hyperswitch (2026-08-14)

Todo lo anterior se probó hablándole directo al gateway. Esto es la otra mitad: el
conector `fiservemea` corriendo dentro del router, que es el camino que va a
producción. Router local contra CERT, expuesto por un túnel público para que el ACS
pueda alcanzar la `methodNotificationURL`.

**44 casos, 41 con el resultado esperado.** Ninguna de las 3 diferencias es del
conector:

| Suite | Resultado |
|---|---|
| 21 casos 3DS (frictionless, method, challenge, challenge+method, dataonly) | 20/21 |
| 13 casos Argentina sin 3DS | 11/13 |
| 10 casos Uruguay | 10/10 |

Cubierto por el router en las dos regiones: venta en 1 pago, dólar, cuotas,
dynamic merchant name, zero auth, captura manual y parcial, void, return total y
parcial, e inquiry con `force_sync`.

Las 3 diferencias: `3DSMethod Rejected` (la discrepancia entre gateway y checklist
ya descrita) y los dos casos de Card on File, que llegan al gateway y chocan con el
servicio no habilitado (pregunta 6).

**Dos hallazgos del lado del conector, ninguno bloquea la homologación:**

1. **El mandato con tarjeta estaba cortado antes de llegar al gateway.** El
   conector heredaba el `validate_mandate_payment` por defecto del router, que
   rechaza todo método de pago. Por eso Card on File figuraba como "nunca
   ejercitado": no faltaba probarlo, no se podía. Corregido; con eso el request
   llega a Fiserv y aparece el punto 6.
2. **`methodNotificationStatus` siempre viaja como `EXPECTED_BUT_NOT_RECEIVED`**,
   incluso cuando el browser sí completó el 3DSMethod y la notificación llegó. El
   dato vive en dos requests distintos y el conector no guarda estado entre ellos.
   El arreglo directo —mandar el PATCH con `RECEIVED` en el callback del método—
   se probó y **rompe el Challenge+Method**: ese request ocurre dentro del iframe
   oculto, así que el desafío se renderiza donde el usuario no lo ve. Requiere
   persistir el estado entre saltos.


Fiserv | Software Express | Twitter | LinkedIn | Facebook

FORTUNE World's Most Admired Companies®


---

# Anexo — Notas de consolidación

Observaciones surgidas al unificar los 8 documentos. No modifican el contenido original: se listan porque son puntos a confirmar con Fiserv durante la homologación.

## Discrepancias entre documentos

| Punto | Documento A | Documento B | Comentario |
|---|---|---|---|
| Código de respuesta `31` | `Códigos-rechazo-declined-failed.pdf`: `N:31:Card not supported` | `Credit cards for test.pdf`: `N:31:Unknown Response Code` | Misma tarjeta de simulación (`5043631200000001` / importe `1031.00`), descripción distinta. Confirmar cuál devuelve el gateway. |
| Versión de la guía | Nombre de archivo: "Argentina 2026" | Portada: "Versión 2.0 — junio 2025 — ARG & URY" | Verificar que sea la versión vigente antes de homologar. |

## Erratas del material original (transcriptas tal cual)

- `§10.4`: el campo figura como `authenticationRequest/athenticationType` (falta la "u"). Confirmar el nombre real esperado por la API.
- `§10.1.5.d`: el JSON de ejemplo del challenge omite una coma después de `"address2": "Suite 123"`, por lo que no es JSON válido tal como está publicado.
- `Zero Auth 2.pdf`: un ejemplo usa comilla tipográfica de apertura en `"value": “{{TokenGateway}}"`, lo que invalida el JSON. Usar comillas rectas.
- `Apéndice VI` ("Transacciones comunes"): el payload de *Sale* venía cortado en el PDF, sin cierre de objeto.
- `Apéndice VII`: el título original dice "mandatories" (en inglés) en un documento en español.

## Tarjetas de prueba que no cumplen Luhn

Se verificaron por algoritmo de Luhn los números de tarjeta transcriptos. Los siguientes, todos de marcas locales argentinas, no validan — es esperable en tarjetas de test de marcas cerradas, pero conviene confirmarlo si el frontend valida Luhn antes de enviar:

`6271700000000000` (KADICARD) · `504408000000000017` (FAVACARD) · `5043631200000001` (NEVADA) · `6391300085755808` (CLUB_LA_NACION) · `5049100100000000` (PYME_NACION) · `6034160000000000` (CONSUMAX) · `501063999000007007` (MAESTRO)

## Payloads del original que no son JSON válido

De los 56 bloques `json` del documento, 51 parsean sin errores. Los 5 restantes reproducen defectos que ya están en el material de Fiserv — se dejaron tal cual porque cambiarlos sería inventar:

| Sección | Problema | Qué hacer |
|---|---|---|
| `Apéndice VI` — payload *Sale* | El PDF corta el JSON sin cerrarlo | La llave de cierre del MD está marcada como agregada |
| `Apéndice VI` — fragmento `"order"` | Es un fragmento, no un objeto completo | Es intencional en el original |
| `Zero Auth §3.3` | `"value": “{{TokenGateway}}"` usa comilla tipográfica de apertura | Reemplazar por comilla recta |
| `§10.1.2` — `methodForm` | Formulario HTML embebido, partido en líneas y con entidades rotas (`& lt;`, `& amp;#10;`) por el renderizado del PDF | No copiar: tomar el valor real de la respuesta de la API |
| `§10.1.5.d` | Falta una coma después de `"address2": "Suite 123"` | Errata del original |

Dos valores largos de `§10.5` (`payerAuthenticationRequest` y `merchantData`) venían partidos en varias líneas en el PDF y acá se unieron en una sola cadena. Conservan artefactos del original (un espacio dentro del base64, espacios alrededor de los guiones del UUID final): son valores de ejemplo, no copiarlos.

Los 12 bloques `xml` del documento parsean todos sin errores.

## Contenido que no sobrevive a la conversión

Los originales contienen capturas de pantalla y diagramas de flujo que no son texto extraíble. Están señalados en línea con `> [Imagen en el documento original]`. Los casos relevantes:

- `§5` — 8 capturas de la configuración de Postman (importar colección, cargar entorno, credenciales, request "API TEST").
- `Comunicacion comercios 3DS.pdf` — infografía de Mastercard y una tabla comparativa que usaba tildes gráficos.
- `Manual NetworkToken MTRG.pdf` — leyendas de color que distinguían parámetros mandatorios de opcionales.
- `Penalizacion por Reintentos Visa - Master.pdf` — los dos adjuntos por Marca eran botones de descarga. **Recuperados** desde los enlaces embebidos en el PDF y transcriptos en la Parte 8 (`TABLA_REINTENTOS_VISA_062024.pdf` y `TABLA_REINTENTOS_MASTERCARD_062024.pdf`).
- `Homologación ... .docx` — los casos obligatorios estaban marcados en rojo; el color no se preserva.
