<?php

namespace KalkanCrypt\Flags;
/**
 * Константы, определяющие значение поля/расширения в запросе/сертификате.
 */
enum CertProp: int
{

    case ISSUER_COUNTRYNAME    =	0x801; /** Страна издателя */
    case ISSUER_SOPN           =	0x802; /** Название штата или провинции издателя */
    case ISSUER_LOCALITYNAME   =	0x803; /** Населённый пункт издателя */
    case ISSUER_ORG_NAME       =	0x804; /** Наименование организации издателя */
    case ISSUER_ORGUNIT_NAME   =	0x805; /** Название организационного подразделения издателя */
    case ISSUER_COMMONNAME     =	0x806; /** Имя Фамилия издателя */

    case SUBJECT_COUNTRYNAME   =	0x807; /** Страна субъекта */
    case SUBJECT_SOPN          =	0x808; /** Название штата или провинции субъекта */
    case SUBJECT_LOCALITYNAME  =	0x809; /** Населенный пункт субъекта */
    case SUBJECT_COMMONNAME    =	0x80a; /** Общее имя субъекта */
    case SUBJECT_GIVENNAME     =	0x80b; /** Имя субъекта */
    case SUBJECT_SURNAME       =	0x80c; /** Фамилия субъекта */
    case SUBJECT_SERIALNUMBER  =	0x80d; /** Серийный номер субъекта */
    case SUBJECT_EMAIL         =	0x80e; /** e-mail субъекта */
    case SUBJECT_ORG_NAME      =	0x80f; /** Наименование организации субъекта */
    case SUBJECT_ORGUNIT_NAME  =	0x810; /** Название организационного подразделения субъекта */
    case SUBJECT_BC            =	0x811; /** Бизнес категория субъекта */
    case SUBJECT_DC            =	0x812; /** Доменный компонент субъекта */

    case NOTBEFORE             =	0x813; /** Дата действителен с */
    case NOTAFTER              =	0x814; /** Дата действителен по */

    case KEY_USAGE             =	0x815; /** Использование ключа */
    case EXT_KEY_USAGE         =	0x816; /** Расширенное использование ключа */

    case AUTH_KEY_ID           =	0x817; /** Идентификатор ключа центра сертификации */
    case SUBJ_KEY_ID           =	0x818; /** Идентификатор ключа субъекта */
    case CERT_SN               =	0x819; /** Серийный номер серификата */


    case ISSUER_DN             =	0x81a; /** Отличительное имя издателя */
    case SUBJECT_DN            =	0x81b; /** Отличительное имя субъекта */


    case SIGNATURE_ALG         =	0x81c; /** Алгоритм подписи */

    case PUBKEY                = 	0x81d; /** Получение открытого ключа */

    case POLICIES_ID           =	0x81e; /** Получение идентификатора политики сертификата */

    case OCSP                  = 	0x81f; /** Получение URL-адреса OCSP */
    case GET_CRL               =	0x820; /** Получение URL-адреса CRL */
    case GET_DELTA_CRL         =	0x821; /** Получение URL-адреса delta CRL */

}
