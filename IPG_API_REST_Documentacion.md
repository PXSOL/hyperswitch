# Fiserv IPG — API REST · Manual de Integración

> **Fuente:** "Guía de Integración API Rest Argentina 2026" (Fiserv Posnet Gateway / IPG) — Versión 2.0, junio 2025.
> **Alcance:** Argentina (ARG) y Uruguay (URY).
> **Nota:** Documento convertido a Markdown desde el PDF original para su implementación. Se preservan todos los payloads JSON, tablas de parámetros y códigos. Los ejemplos que muestran `country` con valores como `USA`, `Germany` o `Singapore`, o monedas `USD`/`EUR`, provienen de la plantilla global de Fiserv/First Data; para ARG/URY usar `ARS` (032) y `UYU` (858).

Este documento está dirigido a desarrolladores que desean integrarse con la solución **IPG de Fiserv** para procesar pagos de e-commerce mediante la opción **REST API**. Requiere conocimientos intermedios-avanzados sobre consumo de servicios web RESTful.

---

## Tabla de contenidos

1. [Introducción](#1-introducción)
2. [Flujo de integración](#2-flujo-de-integración)
3. [Primeros pasos](#3-primeros-pasos)
4. [Estructura de las solicitudes HTTP](#4-estructura-de-las-solicitudes-http)
5. [Configuración del entorno de pruebas](#5-configuración-del-entorno-de-pruebas)
6. [Definición de los endpoints](#6-definición-de-los-endpoints)
7. [Transacciones básicas](#7-transacciones-básicas)
8. [Link de Pago (Payment URL)](#8-link-de-pago-payment-url)
9. [Tokenización](#9-tokenización)
10. [3D Secure](#10-3d-secure)
11. [Pagos recurrentes](#11-pagos-recurrentes)
12. [Payment Facilitator](#12-payment-facilitator)
13. [Tax Refund Uruguay](#13-tax-refund-uruguay)
14. [Buenas prácticas y anotaciones técnicas](#14-buenas-prácticas-y-anotaciones-técnicas)
15. [Wallet](#15-wallet)
- [Apéndice I. Estructura de objetos JSON](#apéndice-i-estructura-de-objetos-json)
- [Apéndice II. Generación de Message-Signature](#apéndice-ii-generación-de-message-signature)
- [Apéndice III. Parámetros de PaymentCardSaleTransaction](#apéndice-iii-parámetros-mandatorios-y-opcionales-de-una-transacción-paymentcardsaletransaction)
- [Apéndice IV. Tarjetas de test (estándar)](#apéndice-iv-tarjetas-de-test-para-integraciones-estándar)
- [Apéndice V. Tarjetas de test para 3DS](#apéndice-v-tarjetas-de-test-para-3ds)
- [Apéndice VI. Transacciones comunes](#apéndice-vi-transacciones-comunes)
- [Apéndice VII. Payment Facilitator (parámetros)](#apéndice-vii-payment-facilitator-parámetros-mandatorios-y-opcionales)

---

## 1. Introducción

IPG es la solución de Fiserv que permite procesar transacciones desde un sitio web a través de un canal seguro. Se adapta a las necesidades del comercio para realizar operaciones bancarias como pagos, devoluciones, cancelaciones, pre-autorizaciones y post-autorizaciones; así como consultar el estatus de las transacciones, generación de Payment URL y personalización completa de la experiencia del comprador.

IPG REST API ofrece un conjunto de herramientas para realizar pagos mediante la definición de un servicio web. **A diferencia de la solución Connect**, la opción REST API permite a los desarrolladores definir por su cuenta el flujo de operación y cobro de las transacciones, así como la personalización completa de los formularios para capturar la información de los tarjetahabientes. Se puede integrar a cualquier tipo de aplicación web, ya que la comunicación consiste en el intercambio de mensajes (solicitudes HTTP) desde la aplicación al servidor de IPG.

La integración por REST API está orientada a un desarrollo más robusto que requiera funcionalidades superiores a la opción Connect. Requiere un equipo de desarrollo más especializado, pero permite que el aplicativo sea escalable y tener control completo del flujo transaccional.

---

## 2. Flujo de integración

La comunicación entre el Gateway de IPG y la aplicación se realiza mediante peticiones HTTP. Estas peticiones son enviadas y procesadas por el servidor de IPG; luego se genera una respuesta que la aplicación debe capturar e interpretar para mostrar el resultado o continuar procesando.

La respuesta puede recibirse en el propio servidor del comercio a través de una URL que permita el método POST. Una vez obtenida la respuesta, es responsabilidad de la lógica de negocio definir qué hacer con ella: almacenarla en base de datos, enviar correos/SMS de confirmación, o mostrar un cuadro de diálogo con el resultado.

---

## 3. Primeros pasos

Para comenzar la integración con la REST API, asegúrate de contar con la siguiente información:

- **API Key** — Clave que identifica al comercio y otorga permiso para procesar transacciones dentro del servidor.
- **API Secret** — Equivalente a una contraseña **PRIVADA**; no debe compartirse. Se usa junto con la API Key para autenticar cada solicitud HTTP.
- **Archivo `postman_environment.json`** — Definición del entorno personalizado para realizar pruebas.
- **Archivo `postman_collection.json`** — Colección de solicitudes HTTP preconstruidas con transacciones de ejemplo para probar la API.

---

## 4. Estructura de las solicitudes HTTP

Una solicitud HTTP se compone de las siguientes partes:

- **Endpoint** — Recurso que vive en un servidor web, consultable desde una aplicación cliente. Tiene estructura de URL, por ejemplo:
  `https://webserver.com/getOrders?param1=value1&param2=value2...&paramn=valuen`
- **Método** — Especifica la operación:
  - `GET` — Obtener información.
  - `POST` — Enviar información.
  - `DELETE` — Borrar un recurso.
  - `PATCH` — Actualizar un recurso existente.
- **Cuerpo/Payload** — Contenido enviado en la solicitud. Solo existe para peticiones `POST` y `PATCH`. IPG REST API admite únicamente objetos JSON en el cuerpo (ver Apéndice I).
- **Encabezados** — Indican al servidor cómo interpretar la solicitud.

Encabezados requeridos en **todas** las peticiones:

| Encabezado | Valor |
|---|---|
| `Content-Type` | `application/json` |
| `Api-Key` | El valor de tu API Key |
| `Client-Request-Id` | Identificador único para cada solicitud. Se sugiere el estándar UUID de 128 bits. Ej. `ED280816-E404-444A-A2D9-FFD2D171F928` |
| `Timestamp` | Número de milisegundos transcurridos desde el 01/01/1970 hasta el instante de la petición (Epoch time). Ej. `1582828266` |
| `Message-Signature` | Hash generado con los datos enviados. Garantiza la autenticidad de la solicitud (ver Apéndice II). |

---

## 5. Configuración del entorno de pruebas

Para probar las transacciones se utiliza la herramienta **Postman**, que permite construir y enviar peticiones HTTP y recibir la respuesta del servidor.

1. Descargar Postman desde `https://www.postman.com/downloads/` (versión 7.18.0 o superior).
2. Instalar la herramienta.
3. En el primer inicio, crear cuenta o continuar sin ella.
4. Importar la colección y el entorno de pruebas (la collection la provee Fiserv) con el botón **Import**.
5. Seleccionar los archivos que terminan en `.postman_collection.json` y `.postman_environment.json` (se pueden cargar ambos a la vez).
6. Verificar que la colección aparezca en **Collections** y el entorno en la lista desplegable superior derecha.
7. Modificar las credenciales: en el engranaje del entorno, completar las variables `api_key` y `api_secret` con las credenciales provistas por Fiserv y presionar **Update**.
8. Ejecutar la request de prueba **"API TEST"** con **Send**. Es importante usar la colección provista, ya que contiene scripts que construyen cada petición automáticamente según la estructura de la documentación.
9. Si el **Status Code** de la respuesta es `200`, ya se puede ejecutar cualquier solicitud de la colección.

---

## 6. Definición de los endpoints

En el entorno de pruebas todas las peticiones deben apuntar a la siguiente URL base:

```
https://cert.api.firstdata.com/gateway/v2
```

Al finalizar las pruebas se proporcionará acceso a un entorno productivo que debe apuntar a una URL de producción.

---

## 7. Transacciones básicas

### 7.1 Conceptos

| Tipo de transacción (Payload) | Descripción |
|---|---|
| **PaymentCardSaleTransaction** | También conocida como "venta". Es el tipo más común. La venta impacta de inmediato en la tarjeta del cliente. |
| **PaymentCardPreAuthTransaction** | "Preautorización". Reserva fondos en la tarjeta de crédito. Es la primera parte de la "compra en 2 pasos". Notas: (a) no se efectúa el pago hasta hacer una captura (postauth) y/o confirmar el envío; (b) **no** es posible operar con preautorización y captura con tarjetas de débito (solo crédito y prepagas); (c) disponible actualmente solo para **Visa y Mastercard**; (d) la preautorización reserva fondos por períodos variables según la política del emisor: se recomienda completar la captura lo antes posible. |
| **PostAuthTransaction** | "Postautorización" o "captura". Captura los fondos reservados por una preautorización, por el monto especificado. Segunda parte de la "compra en 2 pasos". Notas: (a) se puede capturar hasta un 10% más que el monto preautorizado (puede ser rechazada por el emisor); (b) si se captura un monto menor, no hay límite salvo que debe ser mayor a 1 peso; (c) disponible solo para **Visa y Mastercard**; (d) no es posible operar preauth+captura con débito (solo crédito y prepagas). |
| **VoidTransaction** \* | "Anulación". Cancela la transacción original por el total cobrado (el tarjetahabiente no verá el movimiento en su resumen). Solo puede efectuarse: (a) para anular un `sale`, únicamente durante el día en que se efectuó, antes del cierre de lote (23:30 h); (b) **no** es posible anular postautorizaciones. |
| **VoidPreAuthTransactions** \* | "Anulación" de una preauth. Solo puede efectuarse dentro de los 21 días (pasado ese plazo, si no se capturó, se depura; si se intenta capturar después, queda a consideración del emisor). No es posible anular postautorizaciones. |
| **ReturnTransaction** | "Devolución". Genera un movimiento de crédito en la cuenta del cliente (el tarjetahabiente verá el cobro y la devolución en su resumen). Solo puede efectuarse: (a) para devolver un `sale`, inmediatamente después del cobro y hasta 180 días después; (b) para devolver una `postauth`, inmediatamente después de la captura y hasta 180 días después; (c) **no** es posible devolver preautorizaciones. |

> **\* Importante:**
> - Para anular una **preauth** debe usarse obligatoriamente el `requestType` `VoidPreAuthTransactions`.
> - Para anular un **sale** o una **postauth** debe usarse obligatoriamente el `requestType` `VoidTransaction`.
> - Si se usan estos `requestType` de otra forma, las transacciones no se anularán, cualquiera sea la respuesta de IPG.

### 7.2 Parámetros mandatorios y opcionales

#### Transacciones primarias

| | |
|---|---|
| **requestType** (siempre mandatorio) | `PaymentCardSaleTransaction` · `PaymentCardPreAuthTransaction` |
| **Campos mandatorios** | `transactionAmount/total` · `transactionAmount/currency` · `paymentMethod/paymentCard/number` · `paymentMethod/paymentCard/expiryDate` |
| **Campos opcionales** | `paymentMethod/paymentCard/securityCode` · `paymentMethod/paymentCard/cardFunction` · `paymentMethod/paymentCard/cardholderName` · `merchantTransactionId` · `transactionOrigin` · `Order/orderId` · `Billing/name` · `Billing/customerId` · `Billing/birthdate` · `Contact/phone` · `Contact/mobilePhone` · `Contact/fax` · `Contact/email` · `Address/address1` · `Address/address2` · `Address/city` · `Address/region` · `Address/postalCode` · `Address/country` · `Shipping/name` · `Shipping/Contact/phone` · `Shipping/Contact/mobilePhone` · `Shipping/Contact/fax` · `Shipping/Contact/email` · `Shipping/Address/company` · `Shipping/Address/address1` · `Shipping/Address/address2` · `Shipping/Address/city` · `Shipping/Address/region` · `Order/Shipping/Address/postalCode` · `SoftDescriptor/dynamicMerchantName` · `additionalDetails/comments` · `additionalDetails/invoicenumber` · `additionalDetails/invoiceperiod` · `additionalDetails/purchaseOrderNumber` · `Order/installmentOptions/numberOfInstallments` \* · `Order/installmentOptions/Interest` \* |

> **\* Para `sale` o `preauth` en cuotas debe añadirse:**
> - Mandatorio: `Order/installmentOptions/numberOfInstallments`
> - Opcional: `Order/installmentOptions/Interest`

#### Transacciones secundarias: PostAuthTransaction

| | |
|---|---|
| **requestType** (siempre mandatorio) | `PostAuthTransaction` |
| **Campos mandatorios** \* | `PATH PARAMS/TransactionID` · `PATH PARAMS/OrderId` |
| **Campos que no aplican** | `paymentMethod/paymentCard/number` · `paymentMethod/paymentCard/expiryDate` |

> **\*** Para postauth debe enviarse solo uno de los dos: `TransactionID` u `OrderID`.

#### Transacciones secundarias: VoidTransaction / VoidPreAuthTransactions

| | |
|---|---|
| **requestType** \* (siempre mandatorio) | `VoidTransaction` · `VoidPreAuthTransactions` |
| **Campos mandatorios** \*\* | `PATH PARAMS/TransactionID` · `PATH PARAMS/OrderId` |

> **\*** Debe enviarse como `requestType`: para void de una preauth → `VoidPreAuthTransactions`; para void de un sale o una postauth → `VoidTransaction`.
> **\*\*** Para void debe enviarse solo uno de los dos: `TransactionID` u `OrderID`.

#### Transacciones secundarias: ReturnTransaction

| | |
|---|---|
| **requestType** (siempre mandatorio) | `ReturnTransaction` |
| **Campos mandatorios** \* | `PATH PARAMS/TransactionID` · `PATH PARAMS/OrderId` · `transactionAmount/total` · `transactionAmount/currency` |

> **\*** Para return debe enviarse solo uno de los dos: `TransactionID` u `OrderID`, además del importe (`total` y `currency`).

### 7.3 Consulta del estado de la transacción

Endpoint para consultar el estatus de una transacción (primaria o secundaria). No requiere payload; se envía el identificador de la transacción u orden en la URL. Se recibe un payload de tipo `TransactionResponse` u `OrderResponse` respectivamente.

Si se consulta el estado de una transacción de un store que forma parte de un grupo de stores (asociados a un mismo nodo), la consulta debe realizarse así:

```
{{base_url}}/payments/{{ipgTransactionId}}?storeId=5923092899
```

---

## 8. Link de Pago (Payment URL)

La REST API de IPG permite generar **URLs de pago de un solo uso** que pueden distribuirse por un canal externo (email, SMS, WhatsApp, etc.). Se generan de forma dinámica. La respuesta es un objeto JSON de tipo `PaymentUrlResponse`.

| Nombre de la transacción (Payload) | Descripción |
|---|---|
| `PaymentUrlRequest` | Crea una URL de un solo uso para concluir una venta. |

Ver ejemplos de payload en el [Apéndice VI](#apéndice-vi-transacciones-comunes).

---

## 9. Tokenización

Los tokens almacenan los detalles de los instrumentos de pago de un cliente para asegurar y agilizar futuras transacciones. Reducen el riesgo de ataques y el requisito de PCI, ya que evitan almacenar los datos de la tarjeta en los sistemas del comercio.

Las transacciones tokenizadas pueden enviarse mediante alguno de estos flujos:

- **a. Tokenización IPG:**
  - a. Token de IPG
  - b. Network Tokens
- **b. Tokenización Passthrough:**
  - a. Tokens externos (únicamente Network Tokens)

### 9.1 Tokenización IPG

IPG puede almacenar datos confidenciales del titular de la tarjeta en una base de datos cifrada en el centro de datos de Fiserv, para usarlos en transacciones posteriores.

#### 9.1.1 Tipos de tokenización IPG

- **Token de IPG:** IPG almacena los datos de la tarjeta (número y fecha de vencimiento) en su **Data Vault**, ofreciendo un token (`hosted data id`) al comercio.
- **Network Tokens:** Tokens generados por las marcas (VISA, Mastercard), que resguardan la información del tarjetahabiente y generan transacciones más seguras. IPG cuenta con servicio de tokenización integrado que permite a un token de IPG (`hosted data id`) resguardar también un Network Token. Para transaccionar con network tokens usando el servicio integrado, debe solicitarse expresamente al equipo de soporte de Fiserv.

#### 9.1.2 Payloads básicos de tokenización

| Tipo de transacción (Payload) | Descripción |
|---|---|
| `PaymentCardPaymentTokenizationRequest` | Crea un token de pago en el servidor de IPG asociándolo a tu tienda. |
| `PaymentTokenSaleTransaction` | Realiza una venta con el token generado previamente. |
| `PaymentTokenPreAuthTransaction` | Realiza una preauth con el token generado previamente. |

#### 9.1.3 Parámetros mandatorios y opcionales

**PaymentCardPaymentTokenizationRequest**

| | |
|---|---|
| **requestType** (siempre mandatorio) | `PaymentCardPaymentTokenizationRequest` |
| **Campos mandatorios** | `createToken/reusable` · `createToken/declineDuplicates` · `paymentMethod/paymentCard/number` · `paymentMethod/paymentCard/expiryDate` |
| **Campos opcionales** \* | `createToken/value` · `paymentMethod/paymentCard/securityCode` |

**PaymentTokenSaleTransaction**

| | |
|---|---|
| **requestType** (siempre mandatorio) | `PaymentTokenSaleTransaction` |
| **Campos mandatorios** | `paymentMethod/paymentToken/value` · `transactionAmount/total` · `transactionAmount/currency` |
| **Campos opcionales** \* | `paymentMethod/paymentCard/securityCode` |
| **Campos que no aplican** | `paymentMethod/paymentCard/number` · `paymentMethod/paymentCard/expiryDate` |

**PaymentTokenPreAuthTransaction**

| | |
|---|---|
| **requestType** (siempre mandatorio) | `PaymentTokenPreAuthTransaction` |
| **Campos mandatorios** | `paymentMethod/paymentToken/value` · `transactionAmount/total` · `transactionAmount/currency` |
| **Campos opcionales** \* | `paymentMethod/paymentCard/securityCode` |
| **Campos que no aplican** | `paymentMethod/paymentCard/number` · `paymentMethod/paymentCard/expiryDate` |

> **\*** Pueden sumarse el resto de los campos opcionales de las transacciones primarias (billing, shipping, additionalDetails o cuotas).

#### 9.1.4 Tokens de IPG: transacciones

Los pagos puntuales (no recurrentes) realizados con tokens de IPG (`hosted data id`) deben realizarse de la siguiente forma.

**9.1.4.1 Generación del Token IPG**

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

> El valor `F57CF893-086C-4DE9-B7EC-9739670308E7` corresponde al token de IPG, también llamado **Hosted Data ID**.

**9.1.4.2 Transacciones con el Token IPG**

VISA:

```json
{
    "transactionAmount": {
        "total": "50.00",
        "currency": "ARS"
    },
    "storeId": "5923080904",
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

**9.1.4.3 Tokenización y Card on File (CoF)**

Las transacciones tokenizadas forman parte del modelo **Card on File (CoF)**, en el cual los datos de la tarjeta se almacenan previamente de forma segura (por tokenización). Permite futuras transacciones sin reingresar los datos, mejorando la experiencia y reduciendo fricción. Común en ecommerce con pagos recurrentes o compras con un solo clic.

**Tipos de transacciones: CIT y MIT**

- **CIT (Cardholder Initiated Transaction):** iniciadas directamente por el titular de la tarjeta (p. ej., una compra desde el sitio del comercio).
- **MIT (Merchant Initiated Transaction):** iniciadas por el comercio sin intervención directa del cliente (p. ej., suscripciones, pagos recurrentes o cobros por servicios previamente autorizados).

Esta distinción es clave para el cumplimiento normativo y el correcto tratamiento por adquirentes y emisores. Al tratarse de una transacción tokenizada iniciada por el tarjetahabiente, debe informarse el parámetro **CIT**. Por ahora, este parámetro está disponible para la marca **Mastercard**.

### 9.2 Tokenización Passthrough

Los comercios con servicios de tokenización propios o de terceros (ajenos a Fiserv e IPG) también pueden enviar sus transacciones tokenizadas, siempre que sea **tokenización de marca (Network Tokens)**.

Los Network Tokens ("tokens de marca") los generan las marcas (VISA, Mastercard), resguardando la información del tarjetahabiente. Cuando el PAN está tokenizado en la red, puede usarse en todo el ecosistema de pago sin actualizarse aún si la tarjeta estuviera vencida o robada. Los tokens tienen período de validez definido por la marca y dejan de ser válidos fuera de la fecha de vencimiento o si la marca los da de baja por fraude.

En este modelo IPG actúa como **modelo de paso (passthrough)**: pasa los datos del token de red a los emisores. Los pagos puntuales (no recurrentes) con Network Tokenization Passthrough se envían así (las transacciones Mastercard requieren un campo adicional):

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
            "expiryDate": { "month": "12", "year": "2029" },
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
        "components": { "subtotal": 110.00 }
    },
    "transactionAmount": {
        "total": 110.00,
        "currency": "ARS",
        "components": { "subtotal": 110.00 }
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

Campos que deben modificar su mensajería para Network Tokenization Passthrough:

| Parámetro | XML Scheme Type | Valor | Observaciones |
|---|---|---|---|
| `CardNumber` | `xs:string` | Token number = 16 caracteres. Ej. `5249451254674815` | Debe viajar el Token, que contará con 16 números como el PAN de una tarjeta. |
| `ExpMonth` | `xs:string` | Token expiration month. Ej. `10` | Mes en que vence el Token. |
| `ExpYear` | `xs:string` | Token expiration year. Ej. `22` | Año en que expira el Token. |
| `TokenCryptogram` | `xs:string` | Cryptogram asociado. Ej. `AgAAAAoAPlUosiUEDQNSgElQEAA=` | Criptograma asociado al Token en cada transacción. Se envía en Base64. |

> El parámetro `CardCodeValue` no será requerido.

---

## 10. 3D Secure

Al usar el Gateway y Fiserv como proveedor de 3-D Secure, la autenticación se realiza en línea con el flujo de transacciones existente. El proceso comienza con una autorización o venta que incluye el deseo de realizar una autenticación 3-D Secure. La autorización se coloca en estado `WAITING` hasta que se complete la autenticación. Durante el proceso, se le puede solicitar al comerciante que actualice la solicitud original una o más veces para avanzar en el flujo. Al final, la transacción original se actualiza con los resultados y se completa la autorización.

Existen dos flujos: **sin fricción (frictionless)** — el emisor no requiere que el titular se autentique — y **desafío (challenge)** — el emisor solicita autenticación adicional del titular.

### 10.1 Implementación de 3DS (autenticación con proveedor propio)

#### 10.1.1 Paso 1: Iniciar un pago

Utilice la tarjeta de pago o el token de pago para iniciar una transacción principal, indicando que se use 3-D Secure. Los `requestType` relevantes para autenticación 3-D Secure son:

- `PaymentCardPreAuthTransaction`
- `PaymentCardSaleTransaction`
- `PaymentTokenPreAuthTransaction`
- `PaymentTokenSaleTransaction`
- `PaymentCardPayerAuthTransaction`

El mensaje debe incluir el objeto `authenticationRequest` con los siguientes valores:

| Atributo | Descripción |
|---|---|
| `authenticationType` | `Secure3DAuthenticationRequest` es el valor predeterminado para la solicitud de autenticación 3DS. |
| `termURL` | URL de callback donde el servidor ACS publica los resultados del proceso de autenticación (ACS = servidor de control de acceso que ejecuta la autenticación del titular). |
| `methodNotificationURL` | Para recibir notificación de la finalización del formulario 3DSMethod. La URL debe ser identificable de forma única para poder asignarla a la transacción correspondiente. Se sugiere pasar una referencia de transacción como cadena de consulta. |
| `challengeIndicator` | (Opcional) Influye en el flujo de autenticación a usar. Si no se envía, el gateway usa el valor predeterminado `01` (sin preferencia). |
| `challengeWindowSize` | (Opcional) Define el tamaño de la ventana de desafío mostrada al cliente. |

Valores disponibles para `challengeIndicator`:

- `01` = Sin preferencia (valor predeterminado).
- `02` = No se solicitó ningún desafío (prefiere que no se realice desafío).
- `03` = Desafío solicitado: Preferencia del Solicitante 3DS.
- `04` = Desafío solicitado: Mandato (mandatos locales o regionales).
- `05` = No se solicitó desafío (análisis de riesgo de transacción ya realizado).
- `06` = No se solicitó desafío (solo uso compartido de datos).
- `07` = No se solicitó desafío (SCA ya realizado).
- `08` = No se solicitó desafío (exención de lista blanca si no se requiere desafío).
- `09` = Desafío solicitado (solicitud de lista blanca si se requiere desafío).

Valores disponibles para `challengeWindowSize`:

- `01` = 250 x 400
- `02` = 390 x 400
- `03` = 500 x 600
- `04` = 600 x 400
- `05` = Full screen

Ejemplo de solicitud de venta con un conjunto mínimo de elementos:

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
            "expiryDate": { "month": "12", "year": "24" }
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

> No todos los emisores admiten la recopilación de datos del navegador mediante el formulario 3DSMethod. En esos casos no se publicarán datos en `methodNotificationURL`, y el flujo debe continuar publicando un estado `EXPECTED_BUT_NOT_RECEIVED`.

#### 10.1.2 Paso 2: Respuesta de autenticación segura

La respuesta incluirá un elemento `3DSMethod`, que genera un iframe oculto para recopilar datos del navegador para los emisores. Debe incluirse en el sitio web como iframe oculto (no se presenta ninguna pantalla al titular).

Se realiza una verificación para determinar si el sistema 3-D Secure funciona y si el titular está inscrito. Si no funciona o el titular no está inscrito, la transacción se procesa normalmente (`transactionStatus = APPROVED || DECLINED`). Si el titular está inscrito, se incluirá un objeto `authenticationResponse` y el estado será `transactionStatus = WAITING`.

El objeto `authenticationResponse` contendrá:

| Atributo | Valor |
|---|---|
| `type` | `3D_SECURE` |
| `version` | `2.1` o `2.2` |
| `secure3DMethod/methodForm` | Datos de formulario HTML con iFrame oculto usado para recopilar los datos del navegador para el emisor. |
| `secure3DMethod/secure3dTransId` | Identificador único para la transacción proporcionado por el servidor ACS del emisor. |

Ejemplo de respuesta:

```json
{
    "clientRequestId": "30dd879c-ee2f-11db-8314-0800200c9a66",
    "apiTraceId": "rrt-0c80a3403e2c2def0-d-ea-28805-6810951-2",
    "ipgTransactionId": "838916029301",
    "transactionType": "SALE",
    "transactionTime": 1518811817,
    "approvedAmount": { "total": 122.04, "currency": "USD" },
    "transactionStatus": "WAITING",
    "authenticationResponse": {
        "type": "3D_SECURE",
        "version": "2.1",
        "secure3dMethod": {
            "methodForm": "<!-- HTML autónomo con iFrame oculto que hace auto-submit al ACS a través de Fiserv (contiene inputs 3DSMethodData / threeDSMethodData) -->",
            "secure3dTransId": "3ac7caa7-aa42-2663-791b-2ac05a542c4a"
        }
    }
}
```

#### 10.1.3 Paso 3: 3DSMethod — Solicitud de notificación y respuesta

El `methodForm` de 3-D Secure proporciona detalles del entorno del titular al ACS del emisor. Contiene el HTML de un iFrame oculto que se incluye en la página web y publica automáticamente la información en el servidor ACS a través de Fiserv. Es un bloque HTML autónomo que no necesita modificarse.

Si se reciben correctamente, los datos se publican en la `methodNotificationURL` original. El mensaje contendrá un campo `threeDSMethodData`: una respuesta JSON codificada en Base64 que contiene el campo `threeDSServerTransID`.

Ejemplo:

```html
<form name="frm" method="POST" action="{value from methodNotificationURL}">
  <input type="hidden" name="threeDSMethodData"
    value="eyJ0aHJlZURTU2VydmVyVHJhbnNJRCI6IjNhYzdjYWE3LWFhNDItMjY2My03OTFiLTJhYzA1YTU0MmM0YSJ9">
</form>
```

`threeDSMethodData` descifrado:

```json
{ "threeDSServerTransID": "3ac7caa7-aa42-2663-791b-2ac05a542c4a" }
```

> El `threeDSServerTransID` no es necesario para otro procesamiento de 3DS, pero se recomienda guardarlo como referencia.

Debe esperar un **mínimo de 10 segundos** para que se complete el POST anterior y luego determinar el estado de notificación del método:

| Estatus | Descripción |
|---|---|
| `RECEIVED` | Envió `methodNotificationURL` en la solicitud inicial y recibió la notificación del ACS en 10 s (mensaje HTTP POST del ACS con un identificador único `secure3dTransId`). |
| `EXPECTED_BUT_NOT_RECEIVED` | Envió `methodNotificationURL` en la solicitud inicial y **no** recibió la notificación del ACS en 10 s. |
| `NOT_EXPECTED` | **No** envió `methodNotificationURL` en la solicitud inicial. |

> Puede haber respuestas duplicadas a la URL de notificación de 3DSMethod o a la termURL (por solicitudes duplicadas del ACS o comportamiento del navegador). Implemente manejo para no enviar solicitudes duplicadas al gateway.

#### 10.1.4 Alternativa A: Flujo Frictionless

**a. Solicitud para continuar con la autenticación 3DS:** notifique al gateway que puede continuar enviando `methodNotificationStatus` mediante una operación **PATCH** sobre la transacción original. Opcionalmente puede incluir la dirección de facturación y el código de seguridad.

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

**b. Respuesta final de 3DS:** si se determina un flujo sin fricción (el cliente fue autenticado por su banco sin interacción directa), se completa 3-D Secure y se procesa la autorización. La respuesta contiene un objeto `secure3dResponse` con el campo `responseCode3dSecure` y la transacción se aprueba o rechaza (`transactionStatus = APPROVED or DECLINED`).

```json
{
    "clientRequestId": "30dd879c-ee2f-11db-8314-0800200c9a66",
    "apiTraceId": "rrt-0c80a3403e2c2def0-d-ea-28805-6810951-2",
    "ipgTransactionId": "838916029301",
    "transactionType": "SALE",
    "transactionTime": 1518811817,
    "approvedAmount": { "total": 122.04, "currency": "USD" },
    "transactionStatus": "APPROVED",
    "schemeTransactionId": "019078743804756",
    "processor": {
        "responseCode": "00",
        "responseMessage": "APPROVED",
        "authorizationCode": "OK7118"
    },
    "secure3dResponse": { "responseCode3dSecure": "1" }
}
```

#### 10.1.5 Alternativa B: Flujo Challenge

El flujo de desafío se activa cuando la transacción no se considera de bajo riesgo o el emisor requiere autenticación adicional del titular. Comienza con una solicitud inicial de Autorización o Venta a través del paso donde se muestra 3DSMethod.

**a. Solicitud para continuar con la autenticación 3DS** (igual que el frictionless, vía PATCH):

```json
{
    "authenticationType": "Secure3D21AuthenticationUpdateRequest",
    "storeId": "12345500000",
    "methodNotificationStatus": "RECEIVED"
}
```

**b. Gateway responde para continuar con la autenticación 3DS:** para el flujo de desafío, `transactionStatus = "WAITING"`. La respuesta contendrá un `authenticationResponse` con:

| Campo | Descripción |
|---|---|
| `type` | `3D_SECURE` |
| `version` | `2.1` o `2.2` |
| `acsURL` | URL donde se deben publicar los valores `cReq` y `sessionData` para el desafío del titular. |
| `termURL` | URL donde se publicarán los resultados de la autenticación. |
| `cReq` | Mensaje de solicitud de desafío codificado, devuelto por el servidor ACS. |
| `sessionData` | Lista codificada de parámetros de sesión. Puede no proporcionarse siempre. |

```json
{
    "clientRequestId": "30dd879c-ee2f-11db-8314-0800200c9a66",
    "apiTraceId": "rrt-0c80a3403e2c2def0-d-ea-28805-6810951-2",
    "ipgTransactionId": "838916029301",
    "transactionType": "SALE",
    "transactionTime": 1518811817,
    "approvedAmount": { "total": 122.04, "currency": "USD" },
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

**c. Challenge del titular de la tarjeta:** envíe los datos al `acsURL` indicado, generalmente mediante un formulario de auto-envío implementado en su sitio. El titular es redirigido al ACS y se le presenta la UI para autenticarse (OTP, app bancaria, etc.). Publique `cReq` y `sessionData` en el `acsURL` con estos nombres de campo:

| Campo | Descripción |
|---|---|
| `cReq` | Todo el mensaje `cReq` codificado en Base64 obtenido antes. |
| `threeDSSessionData` | Todo el mensaje `sessionData` codificado en Base64 obtenido antes. |

```html
<form name="frm" method="POST" action="https://3ds-acs.test.modirum.com/mdpayacs/pareq">
  <input type="hidden" name="creq" value="ewogICAiYWNzVHJhbCIgOiA...wMDAtMDAwMDAwMDA0MWE5Igp9">
  <input type="hidden" name="threeDSSessionData" value="50F2156E03083CA665BCB4..">
</form>
```

Al completarse la autenticación, se publicará una respuesta en la URL del campo `termURL`.

**d. Solicitud para completar la transacción:** tras recibir los datos del ACS, envíelos al Gateway en el elemento `cRes` junto con la referencia a la transacción original, mediante una solicitud **PATCH**:

| Campo | Valor |
|---|---|
| `authenticationType` | `Secure3D21AuthenticationUpdateRequest` |
| `acsResponse/cRes` | Los datos `cRes` publicados en `termURL` por el servidor ACS. |

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
    "acsResponse": {
        "cRes": "ewogICAiYWNzUmVmZX…Fuc1N0YXR…IKfQ=="
    }
}
```

**e. Última respuesta:** como la transacción se inició como `Sale`, la autorización se realiza en este paso final si la autenticación fue exitosa. La respuesta contiene `secure3dResponse` con `responseCode3dSecure`:

```json
{
    "clientRequestId": "30dd879c-ee2f-11db-8314-0800200c9a66",
    "apiTraceId": "rrt-0c80a3403e2c2def0-d-ea-28805-6810951-2",
    "ipgTransactionId": "838916029301",
    "transactionType": "SALE",
    "transactionTime": 1518811817,
    "approvedAmount": { "total": 122.04, "currency": "USD" },
    "transactionStatus": "APPROVED",
    "schemeTransactionId": "019078743804756",
    "processor": {
        "responseCode": "00",
        "responseMessage": "APPROVED",
        "authorizationCode": "OK7118"
    },
    "secure3dResponse": { "responseCode3dSecure": "1" }
}
```

Variante equivalente para el protocolo 3DS v1 (PATCH con `payerAuthenticationResponse`):

```
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

Respuesta que indica que la autorización se realizó correctamente y se marcó como autenticada:

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
            "expiryDate": { "month": "12", "year": "2024" },
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
        "avsResponse": { "streetMatch": "N", "postalCodeMatch": "N" }
    }
}
```

#### 10.1.6 Data Only (solo Mastercard)

Modalidad disponible únicamente para **Mastercard**. Debe agregarse dentro de `authenticationRequest` el parámetro `messageCategory` con el valor `80`.

Request:

```json
{
    "transactionAmount": { "total": "110.00", "currency": "ARS" },
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
            "expiryDate": { "month": "12", "year": "29" }
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
        "installmentOptions": { "numberOfInstallments": 1 }
    }
}
```

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
            "expiryDate": { "month": "12", "year": "2029" },
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
        "components": { "subtotal": 5.00 }
    },
    "transactionAmount": {
        "total": 5.00,
        "currency": "ARS",
        "components": { "subtotal": 5.00 }
    },
    "transactionStatus": "APPROVED",
    "approvalCode": "Y:051444:4642140429:PPXX:0514440332",
    "secure3dResponse": { "responseCode3dSecure": "A" },
    "processor": {
        "referenceNumber": "051444051444",
        "authorizationCode": "051444",
        "responseCode": "00",
        "responseMessage": "Function performed error-free",
        "avsResponse": { "streetMatch": "NO_INPUT_DATA", "postalCodeMatch": "NO_INPUT_DATA" },
        "securityCodeResponse": "NOT_CHECKED"
    }
}
```

### 10.2 Implementación de 3DS Passthrough (autenticación con proveedor externo)

Si usa su propio proveedor 3DS (o externo) y planea enviar la autorización al Gateway, debe enviar los valores de autenticación obtenidos de su proveedor en el objeto `authenticationResult`:

| Field | Descripción |
|---|---|
| `authenticationType` | Usado para enviar el resultado de autenticación realizado por un proveedor 3-D Secure externo. |
| `cavv` | Valor de autenticación obtenido en la respuesta del proveedor 3-D Secure externo. |
| `dsTransactionId` | ID de referencia de la transacción de autenticación, obtenido del proveedor 3-D Secure externo. |
| `authenticationResponse` | Resultado de la autenticación. Valores permitidos: `Y` = transacción totalmente autenticada, `A` = intento exitoso de autenticación, `U` = no se pudo autenticar por DS o ACS. |

#### 10.2.1 3DS Full Authentication Passthrough

Request (venta ya autenticada por un proveedor externo):

```json
{
    "requestType": "PaymentCardSaleTransaction",
    "transactionAmount": { "total": "12.00", "currency": "EUR" },
    "paymentMethod": {
        "paymentCard": {
            "number": "401699XXXX0006",
            "securityCode": "999",
            "expiryDate": { "month": "12", "year": "24" }
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

Response (aprobada y marcada como totalmente autenticada):

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
            "expiryDate": { "month": "12", "year": "2024" },
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
        "avsResponse": { "streetMatch": "Y", "postalCodeMatch": "Y" },
        "securityCodeResponse": "MATCHED"
    }
}
```

#### 10.2.2 3DS Data Only Passthrough

Modalidad disponible únicamente para **Mastercard**. Debe agregarse dentro de `authenticationResult`:

| Campo | Descripción o Valor |
|---|---|
| `authenticationType` | `Secure3DAuthenticationResult` |
| `authenticationResponse` | `U` |
| `cavv` | Criptograma recibido en la autenticación Data Only. Ej. `AAABCZIhcQAAAABZlyFxAAAAAAA` |
| `dsTransactionId` | Código de identificación de la transacción según el Directory Server. |
| `transactionStatus` | `Y` |
| `messageCategory` | `80` |

Request:

```json
{
    "transactionAmount": { "total": "5.00", "currency": "ARS" },
    "requestType": "PaymentCardSaleTransaction",
    "storeId": "59123456789",
    "paymentMethod": {
        "paymentCard": {
            "number": "5165850000000008",
            "securityCode": "123",
            "expiryDate": { "month": "12", "year": "29" }
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
            "expiryDate": { "month": "12", "year": "2029" },
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
        "components": { "subtotal": 5.00 }
    },
    "transactionAmount": {
        "total": 5.00,
        "currency": "ARS",
        "components": { "subtotal": 5.00 }
    },
    "transactionStatus": "APPROVED",
    "approvalCode": "Y:052256:4642141445:PPXX:0522560333",
    "secure3dResponse": { "responseCode3dSecure": "A" },
    "processor": {
        "referenceNumber": "052256052256",
        "authorizationCode": "052256",
        "responseCode": "00",
        "responseMessage": "Function performed error-free",
        "avsResponse": { "streetMatch": "NO_INPUT_DATA", "postalCodeMatch": "NO_INPUT_DATA" },
        "securityCodeResponse": "NOT_CHECKED"
    }
}
```

### 10.3 Códigos de respuesta de autenticación y condiciones para el paso a la autorización

| Código 3dsecure | Caso de uso | Valor ECI | Proceso de autorización |
|---|---|---|---|
| `1` | Transacción completamente autenticada (con CAVV/AAV) | ECI2/ECI5 | Mensaje de autorización enviado al procesador. |
| `3` | Autenticación fallida (rechazada por DS o ACS) | ECI7 | La autorización es declinada por el gateway con respuesta `N:-50716:3D Secure authentication failed`. |
| `4` | Intento de autenticación (successful attempt). El tarjetahabiente no se pudo autenticar en el portal del emisor. | ECI1/ECI6 | Se envía autorización al procesador; el comercio puede decidir bloquear transacciones con ECI 1 y ECI 6 a nivel tienda. |
| `5` | No es posible autenticar por error del DS — usado en la versión 1 del protocolo 3DS. | ECI7 | Se envía autorización al procesador; el comercio puede bloquear todas las transacciones con ECI 7 a nivel tienda. |
| `6` | No se puede autenticar (con el ACS o DS). | ECI7 | Se envía autorización al procesador; el comercio puede bloquear todas las transacciones con ECI 7 a nivel tienda. |
| `7` | Falló la autenticación (la tarjeta no está registrada en el DS) — usado en la V1 del protocolo 3DS. | ECI7 | Se envía autorización al procesador; el comercio puede bloquear todas las transacciones con ECI 7 a nivel tienda. |
| `8` | Valores o combinación de elementos de autenticación no válidos. | N/A | La transacción es declinada por el gateway con respuesta `N:-5100:Invalid 3D Secure values` (relevante para protocolo 3DS V1). |
| `A` | Transacción Mastercard Insights / Data Only exitosa. | ECI7 | Se envía autorización al procesador; el comercio puede bloquear todas las transacciones con ECI 7 a nivel tienda. |
| `B` | Transacción Mastercard Insights / Data Only no exitosa. | ECI7 | Se envía autorización al procesador; el comercio puede bloquear todas las transacciones con ECI 7 a nivel tienda. |

### 10.4 Campos mandatorios y opcionales de una transacción autenticada con 3DS

| | |
|---|---|
| **requestType posibles** (siempre mandatorio) | `PaymentCardSaleTransaction` · `PaymentCardPreAuthTransaction` |
| **Campos mandatorios adicionales para 3DS** | `authenticationRequest/authenticationType` · `authenticationRequest/authenticationType/termURL` · `authenticationRequest/authenticationType/methodNotificationURL` · Parámetros mandatorios de la transacción primaria elegida \* |
| **Campos opcionales adicionales para 3DS** | `authenticationRequest/authenticationType/messageCategory` \*\* · `authenticationRequest/authenticationType/challengeWindowSize` · `authenticationRequest/authenticationType/browserJavaScriptEnabled` · `authenticationRequest/authenticationType/browserJavaEnabled` · `authenticationRequest/authenticationType/authenticationIndicator` |
| **Campos sugeridos adicionales para 3DS** | `paymentMethod/paymentCard/cardholderName` · `Order/Billing/name` · `Order/Billing/Contact/Phone` · `Order/Billing/Contact/MobilePhone` · `Order/Billing/Contact/Email` · `Order/Billing/Address/Address1` · `Order/Billing/Address/City` · `Order/Billing/Address/PostalCode` · `Order/Billing/Address/Country` · `Order/Shipping/Address/Address1` · `Order/Shipping/Address/City` · `Order/Shipping/Address/postalCode` |

> **\*** Deben adicionarse al resto de los campos mandatorios de la transacción elegida (`PaymentCardSaleTransaction` o `PaymentCardPreAuthTransaction`).
> **\*\*** El campo `messageCategory` es mandatorio para la modalidad **3DS Data Only**, con el valor `80`. Servicio disponible solo para **Mastercard**.

### 10.5 Ejemplo de transacción autenticada con 3DS

```json
{
    "transactionAmount": { "total": "1.00", "currency": "ARS" },
    "requestType": "PaymentCardSaleTransaction",
    "paymentMethod": {
        "paymentCard": {
            "number": "5579220000000012",
            "securityCode": "123",
            "expiryDate": { "month": "12", "year": "22" }
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

La respuesta de IPG (protocolo 3DS v1) incluirá un `authenticationResponse` con `payerAuthenticationRequest`, `termURL`, `merchantData` y `acsURL` dentro de `params`, para redirigir al titular al ACS.

---

## 11. Pagos recurrentes

Los pagos recurrentes (Recurring Payments) son transacciones en las que un consumidor autoriza a un comercio a debitar su cuenta o tarjeta de forma regular (suscripciones de streaming, gimnasios, software, etc.).

### 11.1 Parámetros de pagos recurrentes

| Parámetro | Descripción |
|---|---|
| `recurringType` | En la primera transacción debe informarse `FIRST`. Para las siguientes, `REPEAT`. |
| `CustomerID` | Valor con el que el comercio identifica al cliente. |
| `invoicePeriod` | Período debitado, en formato `MM/AA`. |
| `TokenCryptogram` | Valor criptográfico generado por el emisor o el sistema de tokenización, que autentica el uso del token. Se usa en la transacción `FIRST` dentro del flujo passthrough de Network Tokenization. |
| `SchemeTransactionId` | Identificador único de la transacción asignado por la marca; debe ser almacenado por el comercio para futuras referencias. Aplicable a **VISA**. |
| `ReferencedSchemeTransactionId` | Debe contener el `SchemeTransactionId` de la transacción `FIRST`. Se usa en las `REPEAT` para vincularlas con la original. Aplicable a **VISA**. |

### 11.2 Recurrencia y Card on File

La tokenización permite almacenar de forma segura los datos de la tarjeta (esquema **Card on File**, CoF) para cobros periódicos sin reingreso de datos.

Las transacciones recurrentes se dividen en dos etapas:

- **Transacción FIRST** (primera del ciclo):
  - **VISA:** en la respuesta el comercio recibe el `SchemeTransactionId` de la transacción original, que debe almacenar. Si se usó Network Tokenization, debe enviarse el criptograma.
  - **Mastercard:** deben adicionarse los parámetros de **3DS Data Only**. Si se usó Network Tokenization, debe enviarse el criptograma.
- **Transacción REPEAT** (subsiguientes):
  - **VISA:** debe informarse el valor recibido en `SchemeTransactionId` de la original, en el campo `ReferencedSchemeTransactionId`. Con Network Tokenization, **no** hace falta enviar el criptograma en las `REPEAT`.
  - **Mastercard:** deben enviarse **sin 3DS**. Con Network Tokenization, **no** hace falta enviar el criptograma en las `REPEAT`.

Según el modelo CoF existen dos tipos: **CIT** (Cardholder Initiated Transaction, iniciadas por el titular) y **MIT** (Merchant Initiated Transaction, iniciadas por el comercio como parte de un acuerdo preexistente). En pagos recurrentes, al ser iniciados por el comercio, debe informarse el parámetro **MIT**. Por ahora, este parámetro está disponible para la marca **Mastercard**.

### 11.3 Pagos recurrentes: transacciones

#### 11.3.1 Pagos recurrentes con Tokens IPG

**11.3.1.1 VISA — a. Transacción FIRST:**

```json
{
    "transactionAmount": { "total": "110.00", "currency": "ARS" },
    "requestType": "PaymentTokenSaleTransaction",
    "storeId": "5923080904",
    "paymentMethod": {
        "paymentToken": {
            "tokenOriginStoreId": "5923080904",
            "value": "C70D810A-0187-491E-BAC1-22AD35984B72"
        }
    },
    "order": {
        "billing": { "customerId": "12345678" },
        "installmentOptions": { "recurringType": "FIRST" },
        "additionalDetails": { "invoicePeriod": "08/25" }
    }
}
```

> En el response de IPG se informará el Transaction ID (de la marca) en `SchemeTransactionId`. El comercio debe guardarlo y enviarlo en las transacciones recurrentes posteriores en `referencedSchemeTransactionId`.

**11.3.1.1 VISA — b. Transacción REPEAT:**

```json
{
    "transactionAmount": { "total": "110.00", "currency": "ARS" },
    "requestType": "PaymentTokenSaleTransaction",
    "storeId": "5923080904",
    "paymentMethod": {
        "paymentToken": {
            "tokenOriginStoreId": "5923080904",
            "value": "C70D810A-0187-491E-BAC1-22AD35984B72"
        }
    },
    "order": {
        "billing": { "customerId": "12345678" },
        "installmentOptions": { "recurringType": "REPEAT" },
        "additionalDetails": { "invoicePeriod": "08/25" }
    },
    "storedCredentials": {
        "sequence": "SUBSEQUENT",
        "scheduled": false,
        "referencedSchemeTransactionId": "098765432112345"
    }
}
```

**11.3.1.2 Mastercard — a. Transacción FIRST:**

```json
{
    "transactionAmount": { "total": "110.00", "currency": "ARS" },
    "requestType": "PaymentTokenSaleTransaction",
    "storeId": "5923080904",
    "paymentMethod": {
        "paymentToken": {
            "tokenOriginStoreId": "5923080904",
            "value": "C70D810A-0187-491E-BAC1-22AD35984B72"
        }
    },
    "order": {
        "billing": { "customerId": "12345678" },
        "installmentOptions": { "recurringType": "FIRST" },
        "additionalDetails": { "invoicePeriod": "08/25" }
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

> Debe adicionarse la mensajería correspondiente a una transacción Card on File iniciada por el comercio (MIT).

**11.3.1.2 Mastercard — b. Transacción REPEAT:**

```json
{
    "transactionAmount": { "total": "110.00", "currency": "ARS" },
    "requestType": "PaymentTokenSaleTransaction",
    "storeId": "5923080904",
    "paymentMethod": {
        "paymentToken": {
            "tokenOriginStoreId": "5923080904",
            "value": "C70D810A-0187-491E-BAC1-22AD35984B72"
        }
    },
    "order": {
        "billing": { "customerId": "12345678" },
        "installmentOptions": { "recurringType": "REPEAT" },
        "additionalDetails": { "invoicePeriod": "08/25" }
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

**11.3.2.1 VISA — a. Transacción FIRST:**

```json
{
    "requestType": "PaymentCardSaleTransaction",
    "storeId": "5923080904",
    "transactionAmount": { "total": "102.00", "currency": "ARS" },
    "paymentMethod": {
        "paymentCard": {
            "number": "4044710000000004",
            "expiryDate": { "month": "12", "year": "29" }
        }
    },
    "order": {
        "tokenRequestorID": "12345678912",
        "tokenECI": "05",
        "billing": { "customerId": "12345678" },
        "installmentOptions": { "recurringType": "FIRST" },
        "additionalDetails": { "invoicePeriod": "08/25" },
        "tokenCryptogram": "AgAAAAoAPlUosiUEDQNSgElQEAA="
    }
}
```

**11.3.2.1 VISA — b. Transacción REPEAT:**

```json
{
    "requestType": "PaymentCardSaleTransaction",
    "storeId": "5923080904",
    "transactionAmount": { "total": "102.00", "currency": "ARS" },
    "paymentMethod": {
        "paymentCard": {
            "number": "4044710000000004",
            "expiryDate": { "month": "12", "year": "29" }
        }
    },
    "order": {
        "tokenRequestorID": "12345678912",
        "tokenECI": "05",
        "billing": { "customerId": "12345678" },
        "installmentOptions": { "recurringType": "REPEAT" },
        "additionalDetails": { "invoicePeriod": "08/25" },
        "tokenCryptogram": "AgAAAAoAPlUosiUEDQNSgElQEAA="
    },
    "storedCredentials": {
        "sequence": "SUBSEQUENT",
        "scheduled": false,
        "referencedSchemeTransactionId": "098765432112345"
    }
}
```

**11.3.2.2 Mastercard — a. Transacción FIRST:**

```json
{
    "requestType": "PaymentCardSaleTransaction",
    "storeId": "5923080904",
    "transactionAmount": { "total": "102.00", "currency": "ARS" },
    "paymentMethod": {
        "paymentCard": {
            "number": "5165850000000008",
            "expiryDate": { "month": "12", "year": "29" }
        }
    },
    "order": {
        "tokenRequestorID": "12345678912",
        "tokenECI": "05",
        "billing": { "customerId": "12345678" },
        "installmentOptions": { "recurringType": "FIRST" },
        "additionalDetails": { "invoicePeriod": "08/25" },
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

**11.3.2.2 Mastercard — b. Transacción REPEAT:**

```json
{
    "requestType": "PaymentCardSaleTransaction",
    "storeId": "5923080904",
    "transactionAmount": { "total": "102.00", "currency": "ARS" },
    "paymentMethod": {
        "paymentCard": {
            "number": "5165850000000008",
            "expiryDate": { "month": "12", "year": "29" }
        }
    },
    "order": {
        "tokenRequestorID": "12345678912",
        "tokenECI": "05",
        "billing": { "customerId": "12345678" },
        "installmentOptions": { "recurringType": "REPEAT" },
        "additionalDetails": { "invoicePeriod": "08/25" },
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

> Los campos `tokenRequestorID` y `tokenECI` son opcionales. Si el comercio obtuvo network tokens autenticados, IPG de Fiserv está habilitado para recibir dichas transacciones. Estos campos son requeridos para esa casuística.

---

## 12. Payment Facilitator

Los **Payment Facilitator (PFAC)** tienen un rol importante en el eCommerce. Las marcas requieren cada vez más información a sus adquirentes para controlar posibles malos usos (p. ej., actividad Cross border de submerchants o transacciones con un rubro/MCC indebido), y definieron marcos regulatorios con multas por incumplimientos: el programa **PIFO** para operaciones con Mastercard y el programa **EMLP** para operaciones con VISA.

Fiserv requiere que todo PFAC que opere en su adquirencia cumpla con el envío de la información detallada más abajo en cada transacción de cobro dentro de los programas PIFO y EMLP. Ante inconsistencias, Fiserv podrá no cursar la autorización a la marca y devolver un rechazo. Si la inconsistencia no fuera detectada y la marca generara penalidades por información errónea, se trasladarán al PFAC. El PFAC debe registrarse (o dar consentimiento a Fiserv para registrarlo) en las plataformas de cada marca para obtener el `PFAC_ID`.

**Condiciones (MCC):** las marcas requieren determinar la actividad de los submerchants. Debe informarse en la mensajería el **MCC (Merchant Category Code)** que refleja el negocio principal del submerchant, asociado al MID del PFAC. Fiserv proporciona al PFAC los distintos MID y `Store_ID` asociados, necesarios para cubrir los rubros habilitados para e-commerce; el PFAC debe rutear a través de estos `Store_ID` las operaciones de sus submerchants según el rubro de cada uno. El mismo MCC debe enviarse como MCC del Merchant y como MCC del Submerchant. Esta condición es **mandatoria**.

### 12.1 Boarding

Durante el onboarding debe tenerse a mano el dato que identifica al PFAC ante las marcas:

```
paymentFacilitatorId
```

Es necesario contar con un `paymentFacilitatorId` para **Visa** y uno para **Mastercard** respectivamente, para operar con cada marca.

### 12.2 Campos obligatorios

Si el submerchant es local, se envía la información del submerchant; si es internacional, se envía la información del PFAC en los campos del submerchant.

| Path/Name | XML Schema type | Value | Observaciones |
|---|---|---|---|
| `mcc` | `xs:string` | Merchant Category Code | Actividad del submerchant o comercio cliente del PFAC. Para conocer los MCC, solicitar apoyo al account operativo. |
| `legalName` | `xs:string` | Razón social del subcomercio | Nombre legal del submerchant. |
| `merchantId` | `xs:string` | — | ID único que identifica unívocamente al submerchant en el PFAC. Dato generado por el PFAC. |
| `address1` | `xs:string` | Dirección física (o legal) del submerchant. Una línea. | Dirección física (o legal) del submerchant. Una línea. |
| `city` | `xs:string` | Ciudad | Ciudad. |
| `postalCode` | `xs:string` | Código Postal | El CP debe enviarse bajo el formato `AAA1234BB`. |
| `region` | `xs:string` | País | ISO 3166-1. |
| `country` | `xs:string` | País | ISO 3166-1. |
| `type` | `xs:string` | Tipo de documento del submerchant | Tipo de documento del submerchant. |
| `number` | `xs:string` | Número de documento del submerchant | Número de documento del submerchant. |
| `DynamicMerchantName` | `xs:string` | — | SoftDescriptor. El prefijo PFAC será asignado por Fiserv durante la integración. |

### 12.3 Request y Response

Ejemplo de Request:

```json
{
    "requestType": "PaymentCardSaleTransaction",
    "transactionAmount": { "total": 10, "currency": "ARS" },
    "storeId": "5923080904",
    "paymentMethod": {
        "paymentCard": {
            "number": "{{test_card}}",
            "securityCode": "123",
            "expiryDate": { "month": "12", "year": "29" }
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
        "softDescriptor": { "dynamicMerchantName": "PFAC123*Submerchat" }
    }
}
```

---

## 13. Tax Refund Uruguay

Uruguay tiene leyes especiales de devolución de impuestos; según la ley se debe enviar un valor diferente en cada caso. Valores posibles:

- `NO_TAX_REFUND`
- `URY_RETURNS_IVA_LAW_17934`
- `URY_RETURNS_IMESI_LAW_18083`
- `URY_RETURNS_AFAM_LAW_18910`
- `URY_TAX_REFUND_LAW_18999`
- `URY_RETURNS_IVA_LAW_19210`

Ejemplo:

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
            "expiryDate": { "month": "12", "year": "29" }
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

---

## 14. Buenas prácticas y anotaciones técnicas

1. **Almacenar las credenciales (API Key y API Secret) de forma segura**, sin que sean accesibles desde un navegador. Sugerencia: guardarlas en una base de datos accesible solo desde hosts autorizados, o en un archivo de configuración en un directorio NO público.
2. Si se usa JavaScript en el sitio, **evitar cualquier log en producción**, ya que los mensajes pueden servir de guía a un agente no autorizado.
3. **Evitar almacenar datos sensibles o credenciales en variables de JavaScript.**
4. Cualquier proceso que consulte credenciales o datos sensibles debe realizarse **del lado del servidor** (PHP, ASP.NET). Nunca consultar la base de datos directamente desde JavaScript. Sugerencia: crear un archivo auxiliar server-side y llamarlo por Ajax, limitando la conexión al host del propio sitio.
5. Como medida adicional, **evitar el listado de directorios** desde el hosting (muchos proveedores lo tienen habilitado por defecto).
6. Para reducir transacciones no reconocidas o fraudulentas, **usar siempre autenticación con 3D Secure**.
7. Si el sitio lo permite, autenticar y llevar registro de todos los usuarios.
8. Para evitar transacciones duplicadas, incluir el parámetro `orderId` dentro del objeto `Order` en las transacciones primarias.

---

## 15. Wallet

Todas las transacciones originadas desde un **QR** y finalizadas desde una **Wallet** deben incluir parámetros adicionales según el caso.

**Transacción con PAN:**

```json
{
    "requestType": "WalletSaleTransaction",
    "storeId": "5923080904",
    "transactionAmount": { "total": "1186", "currency": "ARS" },
    "walletPaymentMethod": {
        "walletType": "DecryptedLatamQRWalletPaymentMethod",
        "decryptedLatamQRWallet": {
            "accountNumber": "4123229999000226",
            "cardCodeValue": "462",
            "expiration": { "month": "12", "year": "31" },
            "walletId": "MODO",
            "walletName": "MODO",
            "walletTransactionId": "012",
            "walletTransactionType": "DYNAMIC_QR_CARD_PAYMENT"
        }
    }
}
```

**Transacción con Network Token (Passthrough):**

```json
{
    "requestType": "WalletSaleTransaction",
    "transactionAmount": { "total": "1901", "currency": "UYU" },
    "order": {
        "tokenCryptogram": "kBAYYgZVLBwEl08klDyU79WE6XqM",
        "tokenRequestorID": "50106190476"
    },
    "walletPaymentMethod": {
        "walletType": "DecryptedLatamQRWalletPaymentMethod",
        "decryptedLatamQRWallet": {
            "accountNumber": "5101980000001115",
            "expiration": { "month": "12", "year": "31" },
            "walletId": "858",
            "walletName": "MODO",
            "walletTransactionId": "901",
            "walletTransactionType": "DYNAMIC_QR_CARD_PAYMENT"
        }
    }
}
```

---

## Apéndice I. Estructura de objetos JSON

La estructura base de un objeto JSON es:

```json
{
    "key1": "value1",
    "key2": "value2",
    "keyN": "valueN"
}
```

Todas las claves (`key`) son cadenas de texto que identifican al valor (`value`). Los valores posibles son: numéricos, cadenas de texto (solo estas van entre comillas), booleanos, otros objetos JSON y arreglos de objetos JSON.

Ejemplo:

```json
{
    "merchantName": "fiserv Mexico",
    "merchantAddress": {
        "street": "Jaime Balmes",
        "streetNumber": "11D",
        "country": "Mexico"
    },
    "contact": [
        { "id": 1, "name": "main", "type": "phone", "value": "55 1102 0600" },
        { "id": 2, "name": "main email", "type": "email", "value": "myemail@mail.com" }
    ]
}
```

---

## Apéndice II. Generación de Message-Signature

Para cada solicitud HTTP es necesario generar un hash (**Message-Signature**) que el servidor usa para validar autenticidad e integridad. Se envía en el header `Message-Signature`.

- **Algoritmo:** HMAC SHA256
- **Encoding:** Base64
- **Firmado con:** el `API SECRET` provisto al comercio por Fiserv

**Paso 1** — Generar una cadena con la estructura:

```
msgSignatureString = API_KEY + CLIENT_REQUEST_ID + TIMESTAMP + PAYLOAD
```

Donde:

- **API_KEY:** clave de acceso a la API provista por Fiserv. Ej. `tOqWgOZAFq6aAYpqyQtAGVkjfo2Qp3lUxd`
- **CLIENT_REQUEST_ID:** identificador único por transacción. Se recomienda UUIDv4 (128 bits).
- **TIMESTAMP:** milisegundos desde el 01/01/1970 (Epoch time). Ej. `1650590066714`
- **PAYLOAD:** cuerpo de la solicitud. Si es nulo, se considera cadena vacía. Debe serializarse **sin espacios en blanco ni saltos de línea**.

| Payload original | Payload enviado |
|---|---|
| `{ "name":"Fiserv", "location": "Jaime Balmes 11D" }` | `{"name":"Fiserv","location":"Jaime Balmes 11D"}` |

**Paso 2** — Firmar la cadena resultante con HMAC SHA256 usando como llave el API SECRET:

```
strHash = HmacSHA256( msgSignatureString, API_SECRET )
```

**Paso 3** — Obtener la representación en Base64. El resultado es el valor del header `Message-Signature`:

```
b64Hash = strToBase64( strHash )
```

---

## Apéndice III. Parámetros (mandatorios y opcionales) de una transacción PaymentCardSaleTransaction

**Campos mandatorios:**

- `requestType`: nombre de la solicitud de la transacción principal.
- `transactionAmount`: monto de la transacción. Se compone de:
  - `total`: importe de la transacción (en números).
  - `currency`: moneda de la transacción (ej. `ARS`).
  - `storeId`: número de store.

**Campos opcionales:**

- `merchantTransactionId`: ID único de la transacción generado por el comercio.
- `ipgTransactionId`: ID de la transacción generado por IPG que referencia una transacción.
- `paymentMethod`: alguno de los métodos de pago que admite el Gateway.
  - `paymentCard`:
    - `number`: número de la tarjeta.
    - `securityCode`: código de seguridad de la tarjeta.
    - `expiryDate`: `month` (mes de vencimiento), `year` (año de vencimiento).
    - `cardFunction`: tipo de tarjeta. Valores: `CREDIT`, `DEBIT`, `PREPAID`.
    - `cardholderName`: nombre del titular de la tarjeta.
  - `paymentFacilitator`: detalles del payment facilitator.
    - `subMerchantData` (al proporcionarlo, la transacción se considera de subMerchant):
      - `mcc`: MCC del submerchant.
      - `legalName`: Legal Name del submerchant.
      - `email`: email del submerchant.
      - `timezone`: timezone del país de la transacción (ej. `America/Buenos_Aires`).
      - `address`: `company`, `address1`, `address2`, `city`, `region`, `postalCode`, `country` (ej. `ARG`).
      - `document`: `type` (ej. `SINGLE_TAX_IDENTIFICATION`), `number`.
      - `merchantId`: ID del submerchant (generado por el PFAC), único por submerchant.
- `order`: detalles del pedido.
  - `orderId`: ID del pedido (si no lo provee el cliente, IPG lo genera).
  - `billing`: `name`, `customerId`, `birthDate`, `contact` (`phone`, `mobilePhone`, `fax`, `email`), `address` (`company`, `address1`, `address2`, `city`, `region`, `postalCode`, `country`).
  - `shipping`: `name`, `contact` (`phone`, `mobilePhone`, `fax`, `email`), `address` (`company`, `address1`, `address2`, `city`, `region`, `postalCode`, `country`).
  - `serviceLocation`: `city`, `state`, `zip`, `country`.
  - `ip`: dirección IPv4 o IPv6.
  - `installmentOptions`:
    - `numberOfInstallments`: número de cuotas.
    - `recurringType`: tipo de pago recurrente (`FIRST` o `REPEAT`).
    - `merchantAdviceCodeSupported`: si el comercio admite el Merchant Advice Code (MAC) para recibir el código de la tabla 55 en una transacción recurrente rechazada (`TRUE` o `FALSE`).
  - `tokenCryptogram`: criptograma del token de red (Network Tokenization).
  - `softDescriptor`: nombre del comercio que aparece en el estado de cuenta.
    - `dynamicMerchantName`: nombre de la tienda.
    - `customerServiceNumber`: teléfono de servicio al cliente (puede aparecer en el estado de cuenta).
    - `mcc`: MCC de 4 dígitos.
  - `additionalDetails`:
    - `merchantParameters`
    - `comments`: comentarios sobre el pago.
    - `invoiceNumber`: número de la factura.
    - `invoicePeriod`: período de facturación en formato `MM/AA`.
    - `purchaseOrderNumber`: número de orden de compra.

> Más información en `https://docs.apis-fiserv.com/latam/docs/test`

---

## Apéndice IV. Tarjetas de test para integraciones estándar

### Argentina

| Tarjeta | Exp | CVV | PaymentMethod |
|---|---|---|---|
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

### Uruguay

| Tarjeta | Exp | CVV | Marca |
|---|---|---|---|
| 4103770000000006 | dic-29 | s/cvv | VISA URUGUAY CRÉDITO |
| 4213000000000005 | dic-29 | s/cvv | VISA URUGUAY DÉBITO (V6) |
| 4345590000000006 | dic-29 | s/cvv | VISA INTERNACIONAL DÉBITO (VD) |
| 4147960000000001 | dic-29 | s/cvv | VISA INTERNACIONAL CRÉDITO (VI) |
| 5101980000000000 | dic-29 | s/cvv | MASTERCARD CRÉDITO URUGUAY (PM NO PROCESADO) |
| 5599260000000006 | dic-29 | s/cvv | MASTERCARD PREPAGA URUGUAY (Afiliados ICA 2189) |

### Simulación de rechazos de emisores según el importe

| Amount | ResponseCode | Response |
|---|---|---|
| 1000.00 | 0 | (aprobada) |
| 1000.01 | unanswered | `N:` |
| 1001.00 | 1 | `N:01:Refer to card issuer` |
| 1002.00 | 2 | `N:02:Refer to special conditions for card issuer` |
| 1003.00 | 3 | `N:03:Invalid merchant` |
| 1005.00 | 5 | `N:05:Do not honour` |
| 1007.00 | 7 | `N:07:Pick-up card, special condition` |
| 1013.00 | 13 | `N:13:Invalid amount` |
| 1014.00 | 14 | `N:14:Invalid card number (no such number)` |
| 1031.00 | 31 | `N:31:Unknown Response Code` |
| 1045.00 | 45 | `N:45:The card can't operate with installments` |
| 1046.00 | 46 | `N:46:Card expired` |
| 1051.00 | 51 | `N:51:Not sufficient fund` |
| 1054.00 | 54 | `N:54:Expired card` |
| 1056.00 | 56 | `N:56:No card record` |
| 1061.00 | 61 | `N:61:Exceeds withdrawal amount limit` |
| 1076.00 | 76 | `N:76:Request phone authorization; if approved, load the retrieve code and leave the operation offline` |
| 1091.00 | 91 | `N:91:Issuer or switch is inoperative` |

---

## Apéndice V. Tarjetas de test para 3DS

El propósito de las tarjetas de prueba 3DS es simular respuestas de la **AUTENTICACIÓN**; no garantizan automáticamente la **AUTORIZACIÓN** aprobada. Cada tarjeta debe usarse solo para el escenario/caso de prueba que admite.

- Fecha de vencimiento de todas las tarjetas = **12-29**
- CVV = **123**

**Authentication Transaction Status:**

| Value | Description |
|---|---|
| `Y` | Fully Authenticated |
| `N` | Not Authenticated, cardholder not enrolled |
| `A` | Attempted Authentication |
| `R` | Rejected Authentication |
| `U` | Unable to Authenticate, ACS Not responding / Invalid 3DS Values received |

### Frictionless Flow

| Escenario | 3DS Response Code | 3DS Transaction Status | Tarjeta |
|---|---|---|---|
| Frictionless - Fully Authenticated | 1 | Y | 41474630 11110083 · 52392907 00000028 |
| Frictionless - Not Authenticated | 3 | N | 41474630 11110091 · 52392907 00000036 |
| Frictionless - Attempted Authentication | 4 | A | 41474630 11110117 · 52392907 00000044 |
| Frictionless - Rejected Authentication | 3 | R | 41474630 11110042 · 40163600 00000085 · 51883400 00000052 |
| Frictionless - Unable to authenticate | 6 | U | 41474630 11110067 · 41474630 11110125 · 52392907 00000069 |

### Frictionless Flow + 3DSMethod

| Escenario | 3DS Response Code | 3DS Transaction Status | Tarjeta |
|---|---|---|---|
| Frictionless - Fully Authenticated | 1 | Y | 40990000 00001978 · 52047400 00002711 |
| Frictionless - Not Authenticated | 3 | N | 40990000 00001986 · 54260640 00425117 |
| Frictionless - Attempted Authentication | 4 | A | 41490115 00000519 · 54260640 00425208 |
| Frictionless - Rejected Authentication | 3 | R | 42658800 00000031 · 52047400 00002778 |
| Frictionless - Unable to authenticate | 6 | U | 42658800 00000080 · 54260640 00425216 |

### Challenge Flow

| Escenario | 3DS Response Code | 3DS Transaction Status | Tarjeta |
|---|---|---|---|
| Challenge - R | 3 | R | 41474630 11110034 · 52392907 00000010 |
| Challenge - configurable response | 1 / 4 / 3 / 6 | Y / A / R-N / U | 41474630 11110059 · 52392907 00000002 |

### Challenge Flow + 3DSMethod

| Escenario | 3DS Response Code | 3DS Transaction Status | Tarjeta |
|---|---|---|---|
| Challenge - R | 3 | R | 41474630 11110034 · 52047400 00002760 |
| Challenge - configurable response | 1 / 4 / 3 / 6 | Y / A / R-N / U | 42658800 00000064 · 52047400 00002745 |

---

## Apéndice VI. Transacciones comunes

**Sale:**

```json
{
    "transactionAmount": { "total": "20.00", "currency": "ARS" },
    "requestType": "PaymentCardSaleTransaction",
    "storeId": "5912345678",
    "paymentMethod": {
        "paymentCard": {
            "number": "5165850000000008",
            "securityCode": "123",
            "expiryDate": { "month": "12", "year": "29" }
        }
    }
}
```

Objetos:

- `requestType` — [string] indica el tipo de transacción a realizar: `PaymentCardSaleTransaction`.
- `transactionAmount` — total a cobrar y moneda: `total` [number] (mín. 0, ej. 122.04); `currency` [string] ISO 4217 (ej. `ARS`).
- `paymentMethod` — información del método de pago: `paymentCard` → `number` (16 dígitos), `securityCode` (3 dígitos CVV), `expiryDate` (`month`, `year`).

Para hacer la transacción en 6 cuotas, agregar:

```json
{
    "order": {
        "installmentOptions": { "numberOfInstallments": 6 }
    }
}
```

**Pre auth:**

```json
{
    "transactionAmount": { "total": "5.00", "currency": "ARS" },
    "requestType": "PaymentCardPreAuthTransaction",
    "storeId": "5912345678",
    "paymentMethod": {
        "paymentCard": {
            "number": "5165850000000008",
            "securityCode": "123",
            "expiryDate": { "month": "12", "year": "29" }
        }
    }
}
```

**Post auth:** apuntar al endpoint sustituyendo el `ipgTransactionId` devuelto por la Pre-Auth exitosa:

```
https://cert.api.firstdata.com/gateway/v2/payments/84533163643
```

```json
{
    "requestType": "PostAuthTransaction",
    "transactionAmount": { "total": "5.00", "currency": "ARS" }
}
```

**Generación de Payment URL:**

```json
{
    "transactionAmount": { "total": "100.00", "currency": "ARS" },
    "storeId": "5912345678",
    "transactionType": "SALE",
    "transactionNotificationURL": "https://www.firstdata.com/es_mx/home.html",
    "clientLocale": { "language": "es", "country": "AR" },
    "installmentOptions": {
        "numberOfInstallments": 6,
        "installmentsInterest": false
    }
}
```

---

## Apéndice VII. Payment Facilitator (parámetros mandatorios y opcionales)

| | |
|---|---|
| **requestType posibles** (siempre mandatorio) | `PaymentCardSaleTransaction` · `PaymentCardPreAuthTransaction` |
| **Campos mandatorios adicionales para PFAC** | `PaymentMethod/paymentFacilitator/externalMerchantId` · `PaymentMethod/paymentFacilitator/paymentFacilitatorId` · `PaymentMethod/paymentFacilitator/name` · `PaymentMethod/paymentFacilitator/subMerchantData/mcc` · `PaymentMethod/paymentFacilitator/subMerchantData/legalname` · `PaymentMethod/paymentFacilitator/subMerchantData/Address/address1` · `PaymentMethod/paymentFacilitator/subMerchantData/Address/city` · `PaymentMethod/paymentFacilitator/subMerchantData/Address/region` \* · `PaymentMethod/paymentFacilitator/subMerchantData/Address/postalCode` · `PaymentMethod/paymentFacilitator/subMerchantData/Address/country` · `PaymentMethod/paymentFacilitator/subMerchantData/Document/Type` · `PaymentMethod/paymentFacilitator/subMerchantData/Document/number` · `PaymentMethod/paymentFacilitator/subMerchantData/merchantId` · `SoftDescriptor/dynamicMerchantName` · Parámetros mandatorios de la transacción primaria elegida \*\* |
| **Campos opcionales adicionales para PFAC** | `PaymentMethod/paymentFacilitator/subMerchantData/Address/address2` |

> **\*** Mandatorio si `Country = USA`.
> **\*\*** Deben adicionarse al resto de los campos mandatorios de la transacción elegida (`PaymentCardSaleTransaction` o `PaymentCardPreAuthTransaction`).

---

*Fin del documento. Convertido desde "Guía de Integración API Rest Argentina 2026" (Fiserv, v2.0, junio 2025) para su implementación por un agente en Claude Code.*
