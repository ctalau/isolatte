<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:c="urn:example:catalog">
  <xsl:output method="text" encoding="UTF-8"/>
  <xsl:template match="/">
    <xsl:for-each select="c:catalog/c:book">
      <xsl:sort select="@id"/>
      <xsl:value-of select="concat(@id, ': ', upper-case(c:title), '&#10;')"/>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>
