<?php

namespace KalkanCrypt\Flags;
use KalkanCrypt\Adapter;

/**
 * Константы, определяющие значение поля/расширения в запросе/сертификате.
 */
enum CertProp: int
{

    case ISSUER_COUNTRYNAME    =	Adapter::KC_CERTPROP_ISSUER_COUNTRYNAME; // Страна издателя
    case ISSUER_SOPN           =	Adapter::KC_CERTPROP_ISSUER_SOPN; // Название штата или провинции издателя
    case ISSUER_LOCALITYNAME   =	Adapter::KC_CERTPROP_ISSUER_LOCALITYNAME; // Населённый пункт издателя
    case ISSUER_ORG_NAME       =	Adapter::KC_CERTPROP_ISSUER_ORG_NAME; // Наименование организации издателя
    case ISSUER_ORGUNIT_NAME   =	Adapter::KC_CERTPROP_ISSUER_ORGUNIT_NAME; //Название организационного подразделения издателя
    case ISSUER_COMMONNAME     =	Adapter::KC_CERTPROP_ISSUER_COMMONNAME; // Имя Фамилия издателя

    case SUBJECT_COUNTRYNAME   =	Adapter::KC_CERTPROP_SUBJECT_COUNTRYNAME; // Страна субъекта
    case SUBJECT_SOPN          =	Adapter::KC_CERTPROP_SUBJECT_SOPN; // Название штата или провинции субъекта
    case SUBJECT_LOCALITYNAME  =	Adapter::KC_CERTPROP_SUBJECT_LOCALITYNAME; // Населенный пункт субъекта
    case SUBJECT_COMMONNAME    =	Adapter::KC_CERTPROP_SUBJECT_COMMONNAME; // Общее имя субъекта
    case SUBJECT_GIVENNAME     =	Adapter::KC_CERTPROP_SUBJECT_GIVENNAME; // Имя субъекта
    case SUBJECT_SURNAME       =	Adapter::KC_CERTPROP_SUBJECT_SURNAME; // Фамилия субъекта
    case SUBJECT_SERIALNUMBER  =	Adapter::KC_CERTPROP_SUBJECT_SERIALNUMBER; // Серийный номер субъекта
    case SUBJECT_EMAIL         =	Adapter::KC_CERTPROP_SUBJECT_EMAIL; // e-mail субъекта
    case SUBJECT_ORG_NAME      =	Adapter::KC_CERTPROP_SUBJECT_ORG_NAME; // Наименование организации субъекта
    case SUBJECT_ORGUNIT_NAME  =	Adapter::KC_CERTPROP_SUBJECT_ORGUNIT_NAME; // Название организационного подразделения субъекта
    case SUBJECT_BC            =	Adapter::KC_CERTPROP_SUBJECT_BC; // Бизнес категория субъекта
    case SUBJECT_DC            =	Adapter::KC_CERTPROP_SUBJECT_DC; // Доменный компонент субъекта

    case NOTBEFORE             =	Adapter::KC_CERTPROP_NOTBEFORE; // Дата действителен с
    case NOTAFTER              =	Adapter::KC_CERTPROP_NOTAFTER; // Дата действителен по
    case KEY_USAGE             =	Adapter::KC_CERTPROP_KEY_USAGE; // Использование ключа
    case EXT_KEY_USAGE         =	Adapter::KC_CERTPROP_EXT_KEY_USAGE; // Расширенное использование ключа
    case AUTH_KEY_ID           =	Adapter::KC_CERTPROP_AUTH_KEY_ID; // Идентификатор ключа центра сертификации
    case SUBJ_KEY_ID           =	Adapter::KC_CERTPROP_SUBJ_KEY_ID; // Идентификатор ключа субъекта
    case CERT_SN               =	Adapter::KC_CERTPROP_CERT_SN; // Серийный номер серификата
    case ISSUER_DN             =	Adapter::KC_CERTPROP_ISSUER_DN; // Отличительное имя издателя
    case SUBJECT_DN            =	Adapter::KC_CERTPROP_SUBJECT_DN; // Отличительное имя субъекта
    case SIGNATURE_ALG         =	Adapter::KC_CERTPROP_SIGNATURE_ALG; // Алгоритм подписи
    case PUBKEY                = 	Adapter::KC_CERTPROP_PUBKEY; // Получение открытого ключа
    case POLICIES_ID           =	Adapter::KC_CERTPROP_POLICIES_ID; // Получение идентификатора политики сертификата
    case OCSP                  = 	Adapter::KC_CERTPROP_OCSP; // Получение URL-адреса OCSP
    case GET_CRL               =	Adapter::KC_CERTPROP_GET_CRL; // Получение URL-адреса CRL
    case GET_DELTA_CRL         =	Adapter::KC_CERTPROP_GET_DELTA_CRL; // Получение URL-адреса delta CRL

}
