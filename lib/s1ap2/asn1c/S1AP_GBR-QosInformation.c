/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../support/r14.4.0/36413-e40.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps`
 */

#include "S1AP_GBR-QosInformation.h"

#include "S1AP_ProtocolExtensionContainer.h"
asn_TYPE_member_t asn_MBR_S1AP_GBR_QosInformation_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct S1AP_GBR_QosInformation, e_RAB_MaximumBitrateDL),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_S1AP_BitRate,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"e-RAB-MaximumBitrateDL"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct S1AP_GBR_QosInformation, e_RAB_MaximumBitrateUL),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_S1AP_BitRate,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"e-RAB-MaximumBitrateUL"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct S1AP_GBR_QosInformation, e_RAB_GuaranteedBitrateDL),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_S1AP_BitRate,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"e-RAB-GuaranteedBitrateDL"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct S1AP_GBR_QosInformation, e_RAB_GuaranteedBitrateUL),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_S1AP_BitRate,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"e-RAB-GuaranteedBitrateUL"
		},
	{ ATF_POINTER, 1, offsetof(struct S1AP_GBR_QosInformation, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_S1AP_ProtocolExtensionContainer_6602P57,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_S1AP_GBR_QosInformation_oms_1[] = { 4 };
static const ber_tlv_tag_t asn_DEF_S1AP_GBR_QosInformation_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_S1AP_GBR_QosInformation_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* e-RAB-MaximumBitrateDL */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* e-RAB-MaximumBitrateUL */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* e-RAB-GuaranteedBitrateDL */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* e-RAB-GuaranteedBitrateUL */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* iE-Extensions */
};
asn_SEQUENCE_specifics_t asn_SPC_S1AP_GBR_QosInformation_specs_1 = {
	sizeof(struct S1AP_GBR_QosInformation),
	offsetof(struct S1AP_GBR_QosInformation, _asn_ctx),
	asn_MAP_S1AP_GBR_QosInformation_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_S1AP_GBR_QosInformation_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	5,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_S1AP_GBR_QosInformation = {
	"GBR-QosInformation",
	"GBR-QosInformation",
	&asn_OP_SEQUENCE,
	asn_DEF_S1AP_GBR_QosInformation_tags_1,
	sizeof(asn_DEF_S1AP_GBR_QosInformation_tags_1)
		/sizeof(asn_DEF_S1AP_GBR_QosInformation_tags_1[0]), /* 1 */
	asn_DEF_S1AP_GBR_QosInformation_tags_1,	/* Same as above */
	sizeof(asn_DEF_S1AP_GBR_QosInformation_tags_1)
		/sizeof(asn_DEF_S1AP_GBR_QosInformation_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_S1AP_GBR_QosInformation_1,
	5,	/* Elements count */
	&asn_SPC_S1AP_GBR_QosInformation_specs_1	/* Additional specs */
};

