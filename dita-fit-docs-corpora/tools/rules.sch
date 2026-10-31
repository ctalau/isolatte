<?xml version="1.0" encoding="UTF-8"?>
<!-- ISO Schematron rules run over the facts XML made by extract.py.
     Python only parses Markdown and resolves relative paths; every check is here. -->
<sch:schema xmlns:sch="http://purl.oclc.org/dsdl/schematron"
            xmlns:xsl="http://www.w3.org/1999/XSL/Transform" queryBinding="xslt">
  <xsl:key name="file" match="f" use="@p"/>
  <xsl:key name="redir" match="redir" use="@p"/>
  <xsl:key name="file-lc" match="f" use="translate(@p, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"/>
  <xsl:key name="pivot" match="pivot" use="concat(@g, '|', @id)"/>

  <sch:pattern id="case">
    <sch:rule context="include|link|img">
      <sch:assert id="R13-path-case" test="@r = '' or starts-with(@r, 'XREPO:') or key('file', @r) or key('redir', @r) or not(key('file-lc', translate(@r, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')))">path differs from the real file only in letter case: <sch:value-of select="@href"/></sch:assert>
    </sch:rule>
  </sch:pattern>

  <sch:pattern id="references">
    <sch:rule context="include">
      <sch:assert id="R01-include-exists" test="starts-with(@r, 'XREPO:') or key('file', @r) or key('file-lc', translate(@r, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))">include target missing: <sch:value-of select="@href"/></sch:assert>
    </sch:rule>
    <sch:rule context="link[starts-with(@r, 'XREPO:')]">
      <sch:report id="I03-cross-repo-ref" test="true()">points into a dependent repository, not checkable here: <sch:value-of select="@href"/></sch:report>
    </sch:rule>
    <sch:rule context="link">
      <sch:assert id="R02-link-exists" test="key('file', @r) or key('redir', @r) or key('file-lc', translate(@r, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))">relative link target missing and not redirected: <sch:value-of select="@href"/></sch:assert>
      <sch:report id="I04-link-via-redirect" test="not(key('file', @r)) and key('redir', @r)">link only works through a redirect: <sch:value-of select="@href"/></sch:report>
    </sch:rule>
    <sch:rule context="img">
      <sch:assert id="R03-img-alt" test="string-length(normalize-space(@alt)) &gt; 0">image without alt text: <sch:value-of select="@href"/></sch:assert>
      <sch:assert id="R04-img-exists" test="@r = '' or starts-with(@r, 'XREPO:') or key('file', @r) or key('file-lc', translate(@r, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))">image file missing: <sch:value-of select="@href"/></sch:assert>
    </sch:rule>
    <sch:rule context="zone">
      <sch:let name="g" value="../meta[@k='zone_pivot_groups']/@v"/>
      <sch:assert id="R05-pivot-declared" test="not(/corpus/pivotgroups) or key('pivot', concat($g, '|', @pivot))">pivot "<sch:value-of select="@pivot"/>" not in group "<sch:value-of select="$g"/>"</sch:assert>
    </sch:rule>
  </sch:pattern>

  <sch:pattern id="metadata">
    <sch:rule context="doc[meta][@inc='no'][not(meta[@k='ms.topic'][translate(@v, 'I', 'i') = 'include'])]">
      <sch:assert id="R06-required-meta" test="meta[@k='title'] and meta[@k='description'] and meta[@k='ms.topic'] and meta[@k='ms.date']">missing one of title/description/ms.topic/ms.date</sch:assert>
    </sch:rule>
    <sch:rule context="meta[@k='ms.topic']">
      <!-- Controlled vocabulary: proxy for a subject scheme. Values used >=5 times in sql-docs+azure-docs. -->
      <sch:assert id="R07-topic-vocab" test="contains(' reference how-to concept-article include tutorial quickstart overview article troubleshooting ui-reference sample best-practice release-notes upgrade-and-migration-article install-set-up-deploy troubleshooting-general error-reference feature-guide faq get-started whats-new generated-reference language-reference troubleshooting-problem-resolution troubleshooting-known-issue product-comparison checklist integration feature-availability limits-and-quotas quickstart-sdk glossary quickstart-arm hub-page quickstart-bicep legal ', concat(' ', @v, ' '))">ms.topic "<sch:value-of select="@v"/>" not in vocabulary</sch:assert>
    </sch:rule>
    <sch:rule context="meta[@k='ms.date']">
      <sch:assert id="R08-date-format" test="string-length(@v) = 8 and number(@v) = number(@v)">ms.date not MM/DD/YYYY: <sch:value-of select="@v"/></sch:assert>
      <sch:report id="I01-date-older-3y" test="string-length(@v) = 8 and number(@v) &lt; 20231031">ms.date older than 3 years: <sch:value-of select="@v"/></sch:report>
    </sch:rule>
  </sch:pattern>

  <sch:pattern id="structure">
    <sch:rule context="h">
      <sch:assert id="R09-heading-skip" test="@prev = 0 or @l &lt;= @prev + 1">heading jumps from H<sch:value-of select="@prev"/> to H<sch:value-of select="@l"/></sch:assert>
    </sch:rule>
    <sch:rule context="code">
      <sch:assert id="R10-code-lang" test="string-length(@lang) &gt; 0">code block without language</sch:assert>
    </sch:rule>
    <sch:rule context="anchor">
      <sch:assert id="R11-anchor-unique" test="not(preceding-sibling::anchor[@id = current()/@id])">duplicate anchor <sch:value-of select="@id"/></sch:assert>
    </sch:rule>
  </sch:pattern>

  <sch:pattern id="terminology">
    <sch:rule context="term">
      <sch:report id="R12-retired-name" test="true()">retired product name: <sch:value-of select="@t"/></sch:report>
    </sch:rule>
    <sch:rule context="extlink">
      <sch:report id="I02-absolute-self-link" test="true()">absolute docs.aws.amazon.com link (key/relative candidate)</sch:report>
    </sch:rule>
  </sch:pattern>
</sch:schema>
