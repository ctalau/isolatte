<xsl:stylesheet version="3.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:value-of select="string-join(catalog/book/title ! upper-case(.), ' | ')"/>
    <xsl:text>&#10;Total: </xsl:text>
    <xsl:value-of select="format-number(sum(catalog/book/@price), '0.00')"/>
    <xsl:text>&#10;</xsl:text>
  </xsl:template>
</xsl:stylesheet>
