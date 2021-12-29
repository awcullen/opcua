// Copyright 2021 Converter Systems LLC. All rights reserved.

package server_test

const testnodeset = `
<UANodeSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd" xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <NamespaceUris>
        <Uri>http://github.com/awcullen/opcua/testserver/</Uri>
    </NamespaceUris>
    <Aliases>
        <Alias Alias="Boolean">i=1</Alias>
        <Alias Alias="SByte">i=2</Alias>
        <Alias Alias="Byte">i=3</Alias>
        <Alias Alias="Int16">i=4</Alias>
        <Alias Alias="UInt16">i=5</Alias>
        <Alias Alias="Int32">i=6</Alias>
        <Alias Alias="UInt32">i=7</Alias>
        <Alias Alias="Int64">i=8</Alias>
        <Alias Alias="UInt64">i=9</Alias>
        <Alias Alias="Float">i=10</Alias>
        <Alias Alias="Double">i=11</Alias>
        <Alias Alias="String">i=12</Alias>
        <Alias Alias="DateTime">i=13</Alias>
        <Alias Alias="Guid">i=14</Alias>
        <Alias Alias="ByteString">i=15</Alias>
        <Alias Alias="XmlElement">i=16</Alias>
        <Alias Alias="NodeId">i=17</Alias>
        <Alias Alias="StatusCode">i=19</Alias>
        <Alias Alias="QualifiedName">i=20</Alias>
        <Alias Alias="LocalizedText">i=21</Alias>
        <Alias Alias="Number">i=26</Alias>
        <Alias Alias="Integer">i=27</Alias>
        <Alias Alias="UInteger">i=28</Alias>
        <Alias Alias="Organizes">i=35</Alias>
        <Alias Alias="HasModellingRule">i=37</Alias>
        <Alias Alias="HasTypeDefinition">i=40</Alias>
        <Alias Alias="HasSubtype">i=45</Alias>
        <Alias Alias="HasProperty">i=46</Alias>
        <Alias Alias="HasComponent">i=47</Alias>
        <Alias Alias="NodeClass">i=257</Alias>
        <Alias Alias="Duration">i=290</Alias>
        <Alias Alias="UtcTime">i=294</Alias>
        <Alias Alias="Argument">i=296</Alias>
        <Alias Alias="Range">i=884</Alias>
        <Alias Alias="EUInformation">i=887</Alias>
        <Alias Alias="EnumValueType">i=7594</Alias>
        <Alias Alias="TimeZoneDataType">i=8912</Alias>
    </Aliases>
    <UAObject NodeId="ns=1;s=Demo" BrowseName="1:Demo">
        <DisplayName>Demo</DisplayName>
        <References>
            <Reference ReferenceType="Organizes" IsForward="false">i=85</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Methods</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.NodeClasses</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Paths</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.References</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.SecurityAccess</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;s=Demo.Methods" BrowseName="1:Methods">
        <DisplayName>Methods</DisplayName>
        <References>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.Methods.MethodIO</Reference>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.Methods.MethodI</Reference>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.Methods.MethodO</Reference>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.Methods.MethodNoArgs</Reference>
        </References>
    </UAObject>
    <UAMethod NodeId="ns=1;s=Demo.Methods.MethodIO" BrowseName="1:MethodIO">
        <DisplayName>MethodIO</DisplayName>
        <Description>Adds 2 unsigned integers. This method is added for compliance testing only.</Description>
        <References>
            <Reference ReferenceType="HasProperty">ns=1;s=Demo.Methods.MethodIO.InputArguments</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.Methods</Reference>
            <Reference ReferenceType="HasProperty">ns=1;s=Demo.Methods.MethodIO.OutputArguments</Reference>
        </References>
    </UAMethod>
    <UAVariable DataType="Argument" ParentNodeId="ns=1;s=Demo.Methods.MethodIO" ValueRank="1" NodeId="ns=1;s=Demo.Methods.MethodIO.InputArguments" ArrayDimensions="2" BrowseName="InputArguments">
        <DisplayName>InputArguments</DisplayName>
        <References>
            <Reference ReferenceType="HasProperty" IsForward="false">ns=1;s=Demo.Methods.MethodIO</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
        </References>
        <Value>
            <uax:ListOfExtensionObject>
                <uax:ExtensionObject>
                    <uax:TypeId>
                        <uax:Identifier>i=297</uax:Identifier>
                    </uax:TypeId>
                    <uax:Body>
                        <uax:Argument>
                            <uax:Name>Summand1</uax:Name>
                            <uax:DataType>
                                <uax:Identifier>i=7</uax:Identifier>
                            </uax:DataType>
                            <uax:ValueRank>-1</uax:ValueRank>
                            <uax:ArrayDimensions></uax:ArrayDimensions>
                            <uax:Description/>
                        </uax:Argument>
                    </uax:Body>
                </uax:ExtensionObject>
                <uax:ExtensionObject>
                    <uax:TypeId>
                        <uax:Identifier>i=297</uax:Identifier>
                    </uax:TypeId>
                    <uax:Body>
                        <uax:Argument>
                            <uax:Name>Summand2</uax:Name>
                            <uax:DataType>
                                <uax:Identifier>i=7</uax:Identifier>
                            </uax:DataType>
                            <uax:ValueRank>-1</uax:ValueRank>
                            <uax:ArrayDimensions></uax:ArrayDimensions>
                            <uax:Description/>
                        </uax:Argument>
                    </uax:Body>
                </uax:ExtensionObject>
            </uax:ListOfExtensionObject>
        </Value>
    </UAVariable>
    <UAVariable DataType="Argument" ParentNodeId="ns=1;s=Demo.Methods.MethodIO" ValueRank="1" NodeId="ns=1;s=Demo.Methods.MethodIO.OutputArguments" ArrayDimensions="1" BrowseName="OutputArguments">
        <DisplayName>OutputArguments</DisplayName>
        <References>
            <Reference ReferenceType="HasProperty" IsForward="false">ns=1;s=Demo.Methods.MethodIO</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
        </References>
        <Value>
            <uax:ListOfExtensionObject>
                <uax:ExtensionObject>
                    <uax:TypeId>
                        <uax:Identifier>i=297</uax:Identifier>
                    </uax:TypeId>
                    <uax:Body>
                        <uax:Argument>
                            <uax:Name>Sum</uax:Name>
                            <uax:DataType>
                                <uax:Identifier>i=7</uax:Identifier>
                            </uax:DataType>
                            <uax:ValueRank>-1</uax:ValueRank>
                            <uax:ArrayDimensions></uax:ArrayDimensions>
                            <uax:Description/>
                        </uax:Argument>
                    </uax:Body>
                </uax:ExtensionObject>
            </uax:ListOfExtensionObject>
        </Value>
    </UAVariable>
    <UAMethod NodeId="ns=1;s=Demo.Methods.MethodI" BrowseName="1:MethodI">
        <DisplayName>MethodI</DisplayName>
        <Description>Receives 1 unsigned integer. This method is added for compliance testing only.</Description>
        <References>
            <Reference ReferenceType="HasProperty">ns=1;s=Demo.Methods.MethodI.InputArguments</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.Methods</Reference>
        </References>
    </UAMethod>
    <UAVariable DataType="Argument" ParentNodeId="ns=1;s=Demo.Methods.MethodI" ValueRank="1" NodeId="ns=1;s=Demo.Methods.MethodI.InputArguments" ArrayDimensions="1" BrowseName="InputArguments">
        <DisplayName>InputArguments</DisplayName>
        <References>
            <Reference ReferenceType="HasProperty" IsForward="false">ns=1;s=Demo.Methods.MethodI</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
        </References>
        <Value>
            <uax:ListOfExtensionObject>
                <uax:ExtensionObject>
                    <uax:TypeId>
                        <uax:Identifier>i=297</uax:Identifier>
                    </uax:TypeId>
                    <uax:Body>
                        <uax:Argument>
                            <uax:Name>Summand1</uax:Name>
                            <uax:DataType>
                                <uax:Identifier>i=7</uax:Identifier>
                            </uax:DataType>
                            <uax:ValueRank>-1</uax:ValueRank>
                            <uax:ArrayDimensions></uax:ArrayDimensions>
                            <uax:Description/>
                        </uax:Argument>
                    </uax:Body>
                </uax:ExtensionObject>
            </uax:ListOfExtensionObject>
        </Value>
    </UAVariable>
    <UAMethod NodeId="ns=1;s=Demo.Methods.MethodO" BrowseName="1:MethodO">
        <DisplayName>MethodO</DisplayName>
        <Description>Returns 1 unsigned integer. This method is added for compliance testing only.</Description>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.Methods</Reference>
            <Reference ReferenceType="HasProperty">ns=1;s=Demo.Methods.MethodO.OutputArguments</Reference>
        </References>
    </UAMethod>
    <UAVariable DataType="Argument" ParentNodeId="ns=1;s=Demo.Methods.MethodO" ValueRank="1" NodeId="ns=1;s=Demo.Methods.MethodO.OutputArguments" ArrayDimensions="1" BrowseName="OutputArguments">
        <DisplayName>OutputArguments</DisplayName>
        <References>
            <Reference ReferenceType="HasProperty" IsForward="false">ns=1;s=Demo.Methods.MethodO</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
        </References>
        <Value>
            <uax:ListOfExtensionObject>
                <uax:ExtensionObject>
                    <uax:TypeId>
                        <uax:Identifier>i=297</uax:Identifier>
                    </uax:TypeId>
                    <uax:Body>
                        <uax:Argument>
                            <uax:Name>Sum</uax:Name>
                            <uax:DataType>
                                <uax:Identifier>i=7</uax:Identifier>
                            </uax:DataType>
                            <uax:ValueRank>-1</uax:ValueRank>
                            <uax:ArrayDimensions></uax:ArrayDimensions>
                            <uax:Description/>
                        </uax:Argument>
                    </uax:Body>
                </uax:ExtensionObject>
            </uax:ListOfExtensionObject>
        </Value>
    </UAVariable>
    <UAMethod NodeId="ns=1;s=Demo.Methods.MethodNoArgs" BrowseName="1:MethodNoArgs">
        <DisplayName>MethodNoArgs</DisplayName>
        <Description>Method without Arguments and without any functionality. This method is added for compliance testing only.</Description>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.Methods</Reference>
        </References>
    </UAMethod>
    <UAMethod NodeId="ns=1;s=Demo.Methods.Method1" BrowseName="1:Method1">
        <DisplayName>Method1</DisplayName>
        <Description>Method without Arguments and without any functionality. This method is added for compliance testing only.</Description>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.NodeClasses</Reference>
        </References>
    </UAMethod>
    <UAMethod NodeId="ns=1;s=Demo.Methods.Method2" BrowseName="1:Method2">
        <DisplayName>Method2</DisplayName>
        <Description>Method without Arguments and without any functionality. This method is added for compliance testing only.</Description>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.Methods.Method1</Reference>
        </References>
    </UAMethod>
    <UAMethod NodeId="ns=1;s=Demo.Methods.Method3" BrowseName="1:Method3">
        <DisplayName>Method3</DisplayName>
        <Description>Method without Arguments and without any functionality. This method is added for compliance testing only.</Description>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.Methods.Method1</Reference>
        </References>
    </UAMethod>
    <UAObject NodeId="ns=1;s=Demo.NodeClasses" BrowseName="1:NodeClasses">
        <DisplayName>NodeClasses</DisplayName>
        <References>
            <Reference ReferenceType="Organizes">i=63</Reference>
            <Reference ReferenceType="Organizes">i=58</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="Organizes">i=33</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Methods.Method1</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo</Reference>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.NodeClasses.Object1</Reference>
            <Reference ReferenceType="Organizes">i=12</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.NodeClasses.Variable</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.NodeClasses.View1</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;s=Demo.NodeClasses.Object1" BrowseName="1:Object1">
        <DisplayName>Object1</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=58</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.NodeClasses</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;s=Demo.NodeClasses.Object2" BrowseName="1:Object2">
        <DisplayName>Object2</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=58</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.NodeClasses.Object1</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;s=Demo.NodeClasses.Object3" BrowseName="1:Object3">
        <DisplayName>Object3</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=58</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.NodeClasses.Object1</Reference>
        </References>
    </UAObject>
    <UAVariable DataType="Double" NodeId="ns=1;s=Demo.NodeClasses.Variable.Property1" BrowseName="1:Property1" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Property1</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
            <Reference ReferenceType="HasProperty" IsForward="false">ns=1;s=Demo.NodeClasses.Variable</Reference>
        </References>
        <Value>
            <uax:Double>0</uax:Double>
        </Value>
    </UAVariable>
    <UAVariable DataType="Double" NodeId="ns=1;s=Demo.NodeClasses.Variable.Property2" BrowseName="1:Property2" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Property2</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
            <Reference ReferenceType="HasProperty" IsForward="false">ns=1;s=Demo.NodeClasses.Variable</Reference>
        </References>
        <Value>
            <uax:Double>0</uax:Double>
        </Value>
    </UAVariable>
    <UAVariable DataType="Double" NodeId="ns=1;s=Demo.NodeClasses.Variable" BrowseName="1:Variable" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Variable</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="HasProperty">ns=1;s=Demo.NodeClasses.Variable.Property1</Reference>
            <Reference ReferenceType="HasProperty">ns=1;s=Demo.NodeClasses.Variable.Property2</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.NodeClasses</Reference>
        </References>
        <Value>
            <uax:Double>0</uax:Double>
        </Value>
    </UAVariable>
    <UAObject NodeId="ns=1;s=Demo.Paths" BrowseName="1:Paths">
        <DisplayName>Paths</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent">ns=1;i=5002</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;i=5002" BrowseName="1:folder1">
        <DisplayName>folder1</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.Paths</Reference>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.Paths.folder1.folder2</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;s=Demo.Paths.folder1.folder2" BrowseName="1:folder2">
        <DisplayName>folder2</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5002</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5003</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;i=5003" BrowseName="1:folder3">
        <DisplayName>folder3</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.Paths.folder1.folder2</Reference>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.Paths.folder1.folder2.folder3.folder4</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;s=Demo.Paths.folder1.folder2.folder3.folder4" BrowseName="1:folder4">
        <DisplayName>folder4</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5003</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5004</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;i=5004" BrowseName="1:folder5">
        <DisplayName>folder5</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.Paths.folder1.folder2.folder3.folder4</Reference>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.Paths.folder1.folder2.folder3.folder4.folder5.folder6</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;s=Demo.Paths.folder1.folder2.folder3.folder4.folder5.folder6" BrowseName="1:folder6">
        <DisplayName>folder6</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5004</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5005</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;i=5005" BrowseName="1:folder7">
        <DisplayName>folder7</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.Paths.folder1.folder2.folder3.folder4.folder5.folder6</Reference>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.Paths.folder1.folder2.folder3.folder4.folder5.folder6.folder7.folder8</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;s=Demo.Paths.folder1.folder2.folder3.folder4.folder5.folder6.folder7.folder8" BrowseName="1:folder8">
        <DisplayName>folder8</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5005</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5006</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;i=5006" BrowseName="1:folder9">
        <DisplayName>folder9</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.Paths.folder1.folder2.folder3.folder4.folder5.folder6.folder7.folder8.folder9.folder10</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.Paths.folder1.folder2.folder3.folder4.folder5.folder6.folder7.folder8</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;s=Demo.Paths.folder1.folder2.folder3.folder4.folder5.folder6.folder7.folder8.folder9.folder10" BrowseName="1:folder10">
        <DisplayName>folder10</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5006</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;s=Demo.References" BrowseName="1:References">
        <DisplayName>References</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5007</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5008</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5009</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5011</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5012</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5010</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5013</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5014</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;i=5007" BrowseName="1:Has3ForwardReferences1">
        <DisplayName>Has3ForwardReferences1</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.References</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=6223</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=6224</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=6225</Reference>
        </References>
    </UAObject>
    <UAVariable DataType="Double" NodeId="ns=1;i=6223" BrowseName="1:ReferencedNode1" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>ReferencedNode1</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5007</Reference>
        </References>
        <Value>
            <uax:Double>0</uax:Double>
        </Value>
    </UAVariable>
    <UAVariable DataType="Double" NodeId="ns=1;i=6224" BrowseName="1:ReferencedNode2" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>ReferencedNode2</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5007</Reference>
        </References>
        <Value>
            <uax:Double>0</uax:Double>
        </Value>
    </UAVariable>
    <UAVariable DataType="Double" NodeId="ns=1;i=6225" BrowseName="1:ReferencedNode3" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>ReferencedNode3</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5007</Reference>
        </References>
        <Value>
            <uax:Double>0</uax:Double>
        </Value>
    </UAVariable>
    <UAObject NodeId="ns=1;i=5008" BrowseName="1:Has3ForwardReferences2">
        <DisplayName>Has3ForwardReferences2</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent">ns=1;i=6234</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.References</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=7010</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=7011</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=7012</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5061</Reference>
            <Reference ReferenceType="HasProperty">ns=1;i=6235</Reference>
        </References>
    </UAObject>
    <UAVariable DataType="Double" NodeId="ns=1;i=6234" BrowseName="1:BaseDataVariable" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>BaseDataVariable</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5008</Reference>
        </References>
        <Value>
            <uax:Double>0</uax:Double>
        </Value>
    </UAVariable>
    <UAMethod NodeId="ns=1;i=7010" BrowseName="1:Method1">
        <DisplayName>Method1</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5008</Reference>
        </References>
    </UAMethod>
    <UAMethod NodeId="ns=1;i=7011" BrowseName="1:Method2">
        <DisplayName>Method2</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5008</Reference>
        </References>
    </UAMethod>
    <UAMethod NodeId="ns=1;i=7012" BrowseName="1:Method3">
        <DisplayName>Method3</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5008</Reference>
        </References>
    </UAMethod>
    <UAObject NodeId="ns=1;i=5061" BrowseName="1:Object">
        <DisplayName>Object</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5008</Reference>
        </References>
    </UAObject>
    <UAVariable DataType="Double" NodeId="ns=1;i=6235" BrowseName="1:Property" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Property</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
            <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=5008</Reference>
        </References>
        <Value>
            <uax:Double>0</uax:Double>
        </Value>
    </UAVariable>
    <UAObject NodeId="ns=1;i=5009" BrowseName="1:Has3ForwardReferences3">
        <DisplayName>Has3ForwardReferences3</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.References</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5056</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5057</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5058</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;i=5056" BrowseName="1:ReferencedNode1">
        <DisplayName>ReferencedNode1</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="Organizes">ns=1;i=5010</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5009</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;i=5010" BrowseName="1:Has3InverseReferences">
        <DisplayName>Has3InverseReferences</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;i=5056</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;i=5057</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;i=5058</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.References</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;i=5057" BrowseName="1:ReferencedNode2">
        <DisplayName>ReferencedNode2</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="Organizes">ns=1;i=5010</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5009</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;i=5058" BrowseName="1:ReferencedNode3">
        <DisplayName>ReferencedNode3</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="Organizes">ns=1;i=5010</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5009</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;i=5011" BrowseName="1:Has3ForwardReferences4">
        <DisplayName>Has3ForwardReferences4</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.References</Reference>
            <Reference ReferenceType="HasProperty">ns=1;i=6226</Reference>
            <Reference ReferenceType="HasProperty">ns=1;i=6227</Reference>
            <Reference ReferenceType="HasProperty">ns=1;i=6228</Reference>
        </References>
    </UAObject>
    <UAVariable DataType="Byte" NodeId="ns=1;i=6226" BrowseName="1:ReferencedNode1" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>ReferencedNode1</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
            <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=5011</Reference>
        </References>
        <Value>
            <uax:Byte>0</uax:Byte>
        </Value>
    </UAVariable>
    <UAVariable DataType="Byte" NodeId="ns=1;i=6227" BrowseName="1:ReferencedNode2" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>ReferencedNode2</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
            <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=5011</Reference>
        </References>
        <Value>
            <uax:Byte>0</uax:Byte>
        </Value>
    </UAVariable>
    <UAVariable DataType="Byte" NodeId="ns=1;i=6228" BrowseName="1:ReferencedNode3" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>ReferencedNode3</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
            <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=5011</Reference>
        </References>
        <Value>
            <uax:Byte>0</uax:Byte>
        </Value>
    </UAVariable>
    <UAObject NodeId="ns=1;i=5012" BrowseName="1:Has3ForwardReferences5">
        <DisplayName>Has3ForwardReferences5</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.References</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5059</Reference>
            <Reference ReferenceType="HasProperty">ns=1;i=6229</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=7013</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;i=5059" BrowseName="1:ReferencedNode1">
        <DisplayName>ReferencedNode1</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5012</Reference>
        </References>
    </UAObject>
    <UAVariable DataType="Double" NodeId="ns=1;i=6229" BrowseName="1:ReferencedNode2" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>ReferencedNode2</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
            <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=5012</Reference>
        </References>
        <Value>
            <uax:Double>0</uax:Double>
        </Value>
    </UAVariable>
    <UAMethod NodeId="ns=1;i=7013" BrowseName="1:ReferencedNode3">
        <DisplayName>ReferencedNode3</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5012</Reference>
        </References>
    </UAMethod>
    <UAObject NodeId="ns=1;i=5013" BrowseName="1:HasInverseAndForwardReferences">
        <DisplayName>HasInverseAndForwardReferences</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.References</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=6230</Reference>
        </References>
    </UAObject>
    <UAVariable DataType="UInt32" NodeId="ns=1;i=6230" BrowseName="1:ReferencedNode" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>ReferencedNode</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5013</Reference>
        </References>
        <Value>
            <uax:UInt32>0</uax:UInt32>
        </Value>
    </UAVariable>
    <UAObject NodeId="ns=1;i=5014" BrowseName="1:HasReferencesWithDifferentParentTypes">
        <DisplayName>HasReferencesWithDifferentParentTypes</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.References</Reference>
            <Reference ReferenceType="HasProperty">ns=1;i=6231</Reference>
            <Reference ReferenceType="HasProperty">ns=1;i=6232</Reference>
            <Reference ReferenceType="HasProperty">ns=1;i=6233</Reference>
            <Reference ReferenceType="HasComponent">ns=1;i=5060</Reference>
        </References>
    </UAObject>
    <!-- <UAObject NodeId="ns=1;i=5062" BrowseName="1:ReferencedNode1">
        <DisplayName>ReferencedNode1</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5015</Reference>
        </References>
    </UAObject> -->
    <!-- <UAObject NodeId="ns=1;i=5063" BrowseName="1:ReferencedNode2">
        <DisplayName>ReferencedNode2</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="i=44" IsForward="false">ns=1;i=5015</Reference>
        </References>
    </UAObject> -->
    <UAObject NodeId="ns=1;i=5064" BrowseName="1:ReferencedNode3">
        <DisplayName>ReferencedNode3</DisplayName>
        <References>
            <!-- <Reference ReferenceType="HasTypeDefinition">i=61</Reference> -->
            <Reference ReferenceType="i=34" IsForward="false">ns=1;i=5015</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;i=5065" BrowseName="1:ReferencedNode4">
        <DisplayName>ReferencedNode4</DisplayName>
        <References>
            <!-- <Reference ReferenceType="HasTypeDefinition">i=61</Reference> -->
            <Reference ReferenceType="i=49" IsForward="false">ns=1;i=5015</Reference>
        </References>
    </UAObject>
    <!-- <UAReferenceType NodeId="ns=1;i=5066" BrowseName="HasOrderedComponentSubtype">
        <DisplayName>HasOrderedComponentSubtype</DisplayName>
        <Description>The type for non-looping hierarchical reference from a node to its component when the order of references matters.</Description>
        <References>
        <Reference ReferenceType="HasSubtype" IsForward="false">i=49</Reference>
        </References>
        <InverseName>OrderedComponentSubtypeOf</InverseName>
    </UAReferenceType> -->
    <!-- <UAObject NodeId="ns=1;i=5067" BrowseName="1:ReferencedNode5">
        <DisplayName>ReferencedNode5</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="ns=1;i=5066" IsForward="false">ns=1;i=5015</Reference>
        </References>
    </UAObject> -->
    <UAObject NodeId="ns=1;i=5015" BrowseName="1:HasReferencesWithRefTypeAndSubType">
        <DisplayName>HasReferencesWithRefTypeAndSubType</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.References</Reference>
        </References>
    </UAObject>
    <UAVariable DataType="Double" NodeId="ns=1;i=6231" BrowseName="1:ReferencedNode1" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>ReferencedNode1</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
            <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=5014</Reference>
        </References>
        <Value>
            <uax:Double>0</uax:Double>
        </Value>
    </UAVariable>
    <UAVariable DataType="Double" NodeId="ns=1;i=6232" BrowseName="1:ReferencedNode2" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>ReferencedNode2</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
            <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=5014</Reference>
        </References>
        <Value>
            <uax:Double>0</uax:Double>
        </Value>
    </UAVariable>
    <UAVariable DataType="Double" NodeId="ns=1;i=6233" BrowseName="1:ReferencedNode3" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>ReferencedNode3</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
            <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=5014</Reference>
        </References>
        <Value>
            <uax:Double>0</uax:Double>
        </Value>
    </UAVariable>
    <UAObject NodeId="ns=1;i=5060" BrowseName="1:ReferencedNode4">
        <DisplayName>ReferencedNode4</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=5014</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;s=Demo.SecurityAccess" BrowseName="1:SecurityAccess">
        <DisplayName>SecurityAccess</DisplayName>
        <References>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.SecurityAccess.AccessLevel_CurrentRead</Reference>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.SecurityAccess.AccessLevel_CurrentRead_NotCurrentWrite</Reference>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.SecurityAccess.AccessLevel_CurrentRead_NotUser</Reference>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.SecurityAccess.AccessLevel_CurrentWrite</Reference>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.SecurityAccess.AccessLevel_CurrentWrite_NotCurrentRead</Reference>
            <Reference ReferenceType="HasComponent">ns=1;s=Demo.SecurityAccess.AccessLevel_CurrentWrite_NotUser</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo</Reference>
        </References>
    </UAObject>
    <UAVariable DataType="Int16" NodeId="ns=1;s=Demo.SecurityAccess.AccessLevel_CurrentRead" BrowseName="1:AccessLevel_CurrentRead" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>AccessLevel_CurrentRead</DisplayName>
        <Description>A Node whose AccessLevel attribute contains 'CurrentRead'. The UserAccessLevel should match the AccessLevel so that it is not more restrictive.</Description>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.SecurityAccess</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
        </References>
        <Value>
            <uax:Int16>0</uax:Int16>
        </Value>
    </UAVariable>
    <UAVariable DataType="Int16" NodeId="ns=1;s=Demo.SecurityAccess.AccessLevel_CurrentRead_NotCurrentWrite" BrowseName="1:AccessLevel_CurrentRead_NotCurrentWrite" UserAccessLevel="1" AccessLevel="1">
        <DisplayName>AccessLevel_CurrentRead_NotCurrentWrite</DisplayName>
        <Description>A Node whose UserAccessLevel contains 'CurrentRead', but explicitly does not include 'CurrentWrite'.</Description>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.SecurityAccess</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
        </References>
        <Value>
            <uax:Int16>0</uax:Int16>
        </Value>
    </UAVariable>
    <UAVariable DataType="Int16" NodeId="ns=1;s=Demo.SecurityAccess.AccessLevel_CurrentRead_NotUser" BrowseName="1:AccessLevel_CurrentRead_NotUser" UserAccessLevel="0" AccessLevel="1">
        <DisplayName>AccessLevel_CurrentRead_NotUser</DisplayName>
        <Description>A Node whose AccessLevel attribute contains 'CurrentRead' but the 'UserAccessLevel' does not contain 'CurrentRead'.</Description>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.SecurityAccess</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
        </References>
        <Value>
            <uax:Int16>0</uax:Int16>
        </Value>
    </UAVariable>
    <UAVariable DataType="Int16" NodeId="ns=1;s=Demo.SecurityAccess.AccessLevel_CurrentWrite" BrowseName="1:AccessLevel_CurrentWrite" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>AccessLevel_CurrentWrite</DisplayName>
        <Description>A Node whose AccessLevel attribute contains 'CurrentWrite'. The UserAccessLevel should match the AccessLevel so that it is not more restrictive.</Description>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.SecurityAccess</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
        </References>
        <Value>
            <uax:Int16>0</uax:Int16>
        </Value>
    </UAVariable>
    <UAVariable DataType="Int16" NodeId="ns=1;s=Demo.SecurityAccess.AccessLevel_CurrentWrite_NotCurrentRead" BrowseName="1:AccessLevel_CurrentWrite_NotCurrentRead" UserAccessLevel="2" AccessLevel="2">
        <DisplayName>AccessLevel_CurrentWrite_NotCurrentRead</DisplayName>
        <Description>A Node whose UserAccessLevel contains CurrentWrite, but explicitly does not include 'CurrentRead'.</Description>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.SecurityAccess</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
        </References>
        <Value>
            <uax:Int16>0</uax:Int16>
        </Value>
    </UAVariable>
    <UAVariable DataType="Int16" NodeId="ns=1;s=Demo.SecurityAccess.AccessLevel_CurrentWrite_NotUser" BrowseName="1:AccessLevel_CurrentWrite_NotUser" UserAccessLevel="0" AccessLevel="2">
        <DisplayName>AccessLevel_CurrentWrite_NotUser</DisplayName>
        <Description>A Node whose AccessLevel attribute contains 'CurrentWrite' but the UserAccessLevel does NOT contain 'CurrentWrite'</Description>
        <References>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.SecurityAccess</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
        </References>
        <Value>
            <uax:Int16>0</uax:Int16>
        </Value>
    </UAVariable>
    <UAObject NodeId="ns=1;s=Demo.Static" BrowseName="1:Static">
        <DisplayName>Static</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
    </UAObject>
    <UAObject NodeId="ns=1;s=Demo.Static.Arrays" BrowseName="1:Arrays">
        <DisplayName>Arrays</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.Boolean</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.Byte</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.ByteString</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.DateTime</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.Double</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.Duration</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.Float</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.Guid</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.Int16</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.Int32</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.Int64</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.LocalizedText</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.QualifiedName</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.SByte</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.String</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.UInt16</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.UInt32</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.UInt64</Reference>
            <!-- <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.Variant</Reference> -->
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays.XmlElement</Reference>
        </References>
    </UAObject>
    <UAVariable DataType="Boolean" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.Boolean" ArrayDimensions="0" BrowseName="1:Boolean" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Boolean</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfBoolean>
                <uax:Boolean>false</uax:Boolean>
                <uax:Boolean>true</uax:Boolean>
                <uax:Boolean>true</uax:Boolean>
                <uax:Boolean>false</uax:Boolean>
                <uax:Boolean>false</uax:Boolean>
                <uax:Boolean>true</uax:Boolean>
                <uax:Boolean>true</uax:Boolean>
                <uax:Boolean>false</uax:Boolean>
            </uax:ListOfBoolean>
        </Value>
    </UAVariable>
    <UAVariable DataType="Byte" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.Byte" ArrayDimensions="0" BrowseName="1:Byte" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Byte</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfByte>
                <uax:Byte>1</uax:Byte>
                <uax:Byte>2</uax:Byte>
                <uax:Byte>3</uax:Byte>
                <uax:Byte>4</uax:Byte>
                <uax:Byte>5</uax:Byte>
                <uax:Byte>6</uax:Byte>
                <uax:Byte>7</uax:Byte>
                <uax:Byte>8</uax:Byte>
            </uax:ListOfByte>
        </Value>
    </UAVariable>
    <UAVariable DataType="ByteString" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.ByteString" ArrayDimensions="0" BrowseName="1:ByteString" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>ByteString</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfByteString>
                <uax:ByteString>EjSrzQ==</uax:ByteString>
                <uax:ByteString>I0WrzQ==</uax:ByteString>
                <uax:ByteString>NFarzQ==</uax:ByteString>
                <uax:ByteString>RWerzQ==</uax:ByteString>
                <uax:ByteString>VnirzQ==</uax:ByteString>
                <uax:ByteString>Z4mrzQ==</uax:ByteString>
                <uax:ByteString>eJq83g==</uax:ByteString>
                <uax:ByteString>iavN7w==</uax:ByteString>
            </uax:ListOfByteString>
        </Value>
    </UAVariable>
    <UAVariable DataType="DateTime" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.DateTime" ArrayDimensions="0" BrowseName="1:DateTime" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>DateTime</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfDateTime>
                <uax:DateTime>2015-01-27T14:09:12Z</uax:DateTime>
                <uax:DateTime>2015-02-27T15:08:23Z</uax:DateTime>
                <uax:DateTime>2015-03-27T16:07:34Z</uax:DateTime>
                <uax:DateTime>2015-04-27T17:06:45Z</uax:DateTime>
                <uax:DateTime>2015-05-27T18:05:56Z</uax:DateTime>
                <uax:DateTime>2015-06-27T19:04:57Z</uax:DateTime>
                <uax:DateTime>2015-07-27T20:03:58Z</uax:DateTime>
                <uax:DateTime>2015-08-27T21:02:59Z</uax:DateTime>
            </uax:ListOfDateTime>
        </Value>
    </UAVariable>
    <UAVariable DataType="Double" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.Double" ArrayDimensions="0" BrowseName="1:Double" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Double</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfDouble>
                <uax:Double>12.345</uax:Double>
                <uax:Double>23.456</uax:Double>
                <uax:Double>34.567</uax:Double>
                <uax:Double>45.678</uax:Double>
                <uax:Double>56.789</uax:Double>
                <uax:Double>67.890</uax:Double>
                <uax:Double>78.901</uax:Double>
                <uax:Double>89.012</uax:Double>
            </uax:ListOfDouble>
        </Value>
    </UAVariable>
    <UAVariable DataType="Duration" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.Duration" ArrayDimensions="0" BrowseName="1:Duration" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Duration</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfDouble>
                <uax:Double>12.345</uax:Double>
                <uax:Double>23.456</uax:Double>
                <uax:Double>34.567</uax:Double>
                <uax:Double>45.678</uax:Double>
                <uax:Double>56.789</uax:Double>
                <uax:Double>67.890</uax:Double>
                <uax:Double>78.901</uax:Double>
                <uax:Double>89.012</uax:Double>
            </uax:ListOfDouble>
        </Value>
    </UAVariable>
    <UAVariable DataType="Float" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.Float" ArrayDimensions="0" BrowseName="1:Float" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Float</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfFloat>
                <uax:Float>12.34</uax:Float>
                <uax:Float>23.45</uax:Float>
                <uax:Float>34.56</uax:Float>
                <uax:Float>45.67</uax:Float>
                <uax:Float>56.78</uax:Float>
                <uax:Float>67.89</uax:Float>
                <uax:Float>78.90</uax:Float>
                <uax:Float>89.01</uax:Float>
            </uax:ListOfFloat>
        </Value>
    </UAVariable>
    <UAVariable DataType="Guid" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.Guid" ArrayDimensions="0" BrowseName="1:Guid" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Guid</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfGuid>
                <uax:Guid>
                    <uax:String>EA292DEC-0F79-43F0-84FF-2E4AC0150919</uax:String>
                </uax:Guid>
                <uax:Guid>
                    <uax:String>3DCF6F59-CA93-4524-8210-FAAA702C17CA</uax:String>
                </uax:Guid>                
                <uax:Guid>
                    <uax:String>9EA788A0-EF31-41CB-BC0F-8402C87DB492</uax:String>
                </uax:Guid>
                <uax:Guid>
                    <uax:String>471D0CEC-08FB-4EB4-96CE-D8902552CB21</uax:String>
                </uax:Guid>
                <uax:Guid>
                    <uax:String>5DD353C3-DAC6-4140-9CAE-B1D855EB885D</uax:String>
                </uax:Guid>
                <uax:Guid>
                    <uax:String>07CB33C8-04C9-4B80-B7F0-4ED048F5984E</uax:String>
                </uax:Guid>
                <uax:Guid>
                    <uax:String>1616F5BA-EF8A-40AC-BBA9-033CD35B2FC7</uax:String>
                </uax:Guid>
                <uax:Guid>
                    <uax:String>53D8AE86-9BCE-4CF9-BD34-1D78FC6C7730</uax:String>
                </uax:Guid>
            </uax:ListOfGuid>
        </Value>
    </UAVariable>
    <UAVariable DataType="Int16" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.Int16" ArrayDimensions="0" BrowseName="1:Int16" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Int16</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfInt16>
                <uax:Int16>-124</uax:Int16>
                <uax:Int16>235</uax:Int16>
                <uax:Int16>-346</uax:Int16>
                <uax:Int16>457</uax:Int16>
                <uax:Int16>-568</uax:Int16>
                <uax:Int16>679</uax:Int16>
                <uax:Int16>-780</uax:Int16>
                <uax:Int16>891</uax:Int16>
            </uax:ListOfInt16>
        </Value>
    </UAVariable>
    <UAVariable DataType="Int32" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.Int32" ArrayDimensions="0" BrowseName="1:Int32" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Int32</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfInt32>
                <uax:Int32>-1247</uax:Int32>
                <uax:Int32>2356</uax:Int32>
                <uax:Int32>-3465</uax:Int32>
                <uax:Int32>4574</uax:Int32>
                <uax:Int32>-5683</uax:Int32>
                <uax:Int32>6792</uax:Int32>
                <uax:Int32>-7801</uax:Int32>
                <uax:Int32>8910</uax:Int32>
            </uax:ListOfInt32>
        </Value>
    </UAVariable>
    <UAVariable DataType="Int64" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.Int64" ArrayDimensions="0" BrowseName="1:Int64" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Int64</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfInt64>
                <uax:Int64>-1247</uax:Int64>
                <uax:Int64>2356</uax:Int64>
                <uax:Int64>-3465</uax:Int64>
                <uax:Int64>4574</uax:Int64>
                <uax:Int64>-5683</uax:Int64>
                <uax:Int64>6792</uax:Int64>
                <uax:Int64>-7801</uax:Int64>
                <uax:Int64>8910</uax:Int64>
            </uax:ListOfInt64>
        </Value>
    </UAVariable>
    <UAVariable DataType="LocalizedText" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.LocalizedText" ArrayDimensions="0" BrowseName="1:LocalizedText" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>LocalizedText</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfLocalizedText>
                <uax:LocalizedText>
                    <uax:Locale>de</uax:Locale>
                    <uax:Text>Hallo Welt</uax:Text>
                </uax:LocalizedText>
                <uax:LocalizedText>
                    <uax:Locale>en</uax:Locale>
                    <uax:Text>Hello world</uax:Text>
                </uax:LocalizedText>
                <uax:LocalizedText>
                    <uax:Locale>de</uax:Locale>
                    <uax:Text>Hallo Welt</uax:Text>
                </uax:LocalizedText>
                <uax:LocalizedText>
                    <uax:Locale>en</uax:Locale>
                    <uax:Text>Hello world</uax:Text>
                </uax:LocalizedText>
                <uax:LocalizedText>
                    <uax:Locale>de</uax:Locale>
                    <uax:Text>Hallo Welt</uax:Text>
                </uax:LocalizedText>
                <uax:LocalizedText>
                    <uax:Locale>en</uax:Locale>
                    <uax:Text>Hello world</uax:Text>
                </uax:LocalizedText>
                <uax:LocalizedText>
                    <uax:Locale>de</uax:Locale>
                    <uax:Text>Hallo Welt</uax:Text>
                </uax:LocalizedText>
                <uax:LocalizedText>
                    <uax:Locale>en</uax:Locale>
                    <uax:Text>Hello world</uax:Text>
                </uax:LocalizedText>
            </uax:ListOfLocalizedText>
        </Value>
    </UAVariable>
    <UAVariable DataType="QualifiedName" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.QualifiedName" ArrayDimensions="0" BrowseName="1:QualifiedName" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>QualifiedName</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfQualifiedName>
                <uax:QualifiedName>
                    <uax:NamespaceIndex>1</uax:NamespaceIndex>
                    <uax:Name>A name in namespace 1</uax:Name>
                </uax:QualifiedName>
                <uax:QualifiedName>
                    <uax:NamespaceIndex>2</uax:NamespaceIndex>
                    <uax:Name>A name in namespace 2</uax:Name>
                </uax:QualifiedName>
                <uax:QualifiedName>
                    <uax:NamespaceIndex>3</uax:NamespaceIndex>
                    <uax:Name>A name in namespace 3</uax:Name>
                </uax:QualifiedName>
                <uax:QualifiedName>
                    <uax:NamespaceIndex>4</uax:NamespaceIndex>
                    <uax:Name>A name in namespace 4</uax:Name>
                </uax:QualifiedName>
                <uax:QualifiedName>
                    <uax:NamespaceIndex>1</uax:NamespaceIndex>
                    <uax:Name>A name in namespace 1</uax:Name>
                </uax:QualifiedName>
                <uax:QualifiedName>
                    <uax:NamespaceIndex>2</uax:NamespaceIndex>
                    <uax:Name>A name in namespace 2</uax:Name>
                </uax:QualifiedName>
                <uax:QualifiedName>
                    <uax:NamespaceIndex>3</uax:NamespaceIndex>
                    <uax:Name>A name in namespace 3</uax:Name>
                </uax:QualifiedName>
                <uax:QualifiedName>
                    <uax:NamespaceIndex>4</uax:NamespaceIndex>
                    <uax:Name>A name in namespace 4</uax:Name>
                </uax:QualifiedName>
            </uax:ListOfQualifiedName>
        </Value>
    </UAVariable>
    <UAVariable DataType="SByte" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.SByte" ArrayDimensions="0" BrowseName="1:SByte" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>SByte</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfSByte>
                <uax:SByte>-128</uax:SByte>
                <uax:SByte>-127</uax:SByte>
                <uax:SByte>-126</uax:SByte>
                <uax:SByte>-125</uax:SByte>
                <uax:SByte>124</uax:SByte>
                <uax:SByte>125</uax:SByte>
                <uax:SByte>126</uax:SByte>
                <uax:SByte>127</uax:SByte>
            </uax:ListOfSByte>
        </Value>
    </UAVariable>
    <UAVariable DataType="String" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.String" ArrayDimensions="0" BrowseName="1:String" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>String</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfString>
                <uax:String>Hello_01</uax:String>
                <uax:String>Hello_02</uax:String>
                <uax:String>Hello_03</uax:String>
                <uax:String>Hello_04</uax:String>
                <uax:String>Hello_05</uax:String>
                <uax:String>Hello_06</uax:String>
                <uax:String>Hello_07</uax:String>
                <uax:String>Hello_08</uax:String>
            </uax:ListOfString>
        </Value>
    </UAVariable>
    <UAVariable DataType="UInt16" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.UInt16" ArrayDimensions="0" BrowseName="1:UInt16" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>UInt16</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfUInt16>
                <uax:UInt16>124</uax:UInt16>
                <uax:UInt16>235</uax:UInt16>
                <uax:UInt16>346</uax:UInt16>
                <uax:UInt16>457</uax:UInt16>
                <uax:UInt16>568</uax:UInt16>
                <uax:UInt16>679</uax:UInt16>
                <uax:UInt16>780</uax:UInt16>
                <uax:UInt16>891</uax:UInt16>
            </uax:ListOfUInt16>
        </Value>
    </UAVariable>
    <UAVariable DataType="UInt32" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.UInt32" ArrayDimensions="0" BrowseName="1:UInt32" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>UInt32</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="HasComponent" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfUInt32>
                <uax:UInt32>12498</uax:UInt32>
                <uax:UInt32>23587</uax:UInt32>
                <uax:UInt32>34676</uax:UInt32>
                <uax:UInt32>45765</uax:UInt32>
                <uax:UInt32>56854</uax:UInt32>
                <uax:UInt32>67943</uax:UInt32>
                <uax:UInt32>78032</uax:UInt32>
                <uax:UInt32>89121</uax:UInt32>
            </uax:ListOfUInt32>
        </Value>
    </UAVariable>
    <UAVariable DataType="UInt64" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.UInt64" ArrayDimensions="0" BrowseName="1:UInt64" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>UInt64</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfUInt64>
                <uax:UInt64>124981</uax:UInt64>
                <uax:UInt64>235872</uax:UInt64>
                <uax:UInt64>346763</uax:UInt64>
                <uax:UInt64>457654</uax:UInt64>
                <uax:UInt64>568545</uax:UInt64>
                <uax:UInt64>679436</uax:UInt64>
                <uax:UInt64>780327</uax:UInt64>
                <uax:UInt64>891218</uax:UInt64>
            </uax:ListOfUInt64>
        </Value>
    </UAVariable>
    <!-- <UAVariable DataType="i=24" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.Variant" ArrayDimensions="0" BrowseName="1:Variant" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Variant</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <Value>
            <uax:ListOfVariant>
                <uax:Boolean>true</uax:Boolean>
                <uax:Int16>234</uax:Int16>
                <uax:Float>23.45</uax:Float>
                <uax:String>Hello world</uax:String>
                <uax:QualifiedName>
                    <uax:NamespaceIndex>4</uax:NamespaceIndex>
                    <uax:Name>A name in namespace 4</uax:Name>
                </uax:QualifiedName>
                <uax:Boolean>true</uax:Boolean>
                <uax:Int16>234</uax:Int16>
                <uax:Float>23.45</uax:Float>
                <uax:String>Hello world</uax:String>
                <uax:QualifiedName>
                    <uax:NamespaceIndex>4</uax:NamespaceIndex>
                    <uax:Name>A name in namespace 4</uax:Name>
                </uax:QualifiedName>
            </uax:ListOfVariant>
        </Value>
    </UAVariable> -->
    <UAVariable DataType="XmlElement" ValueRank="1" NodeId="ns=1;s=Demo.Static.Arrays.XmlElement" ArrayDimensions="0" BrowseName="1:XmlElement" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>XmlElement</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Arrays</Reference>
        </References>
        <?xml version="1.0" encoding="UTF-8"?>
        <Value>
            <uax:ListOfXmlElement>
                <uax:XmlElement><foo>bar0</foo></uax:XmlElement>
                <uax:XmlElement><foo>bar1</foo></uax:XmlElement>
                <uax:XmlElement><foo>bar2</foo></uax:XmlElement>
                <uax:XmlElement><foo>bar3</foo></uax:XmlElement>
                <uax:XmlElement><foo>bar4</foo></uax:XmlElement>
                <uax:XmlElement><foo>bar5</foo></uax:XmlElement>
                <uax:XmlElement><foo>bar6</foo></uax:XmlElement>
                <uax:XmlElement><foo>bar7</foo></uax:XmlElement>
            </uax:ListOfXmlElement>
        </Value>
    </UAVariable>
    <UAObject NodeId="ns=1;s=Demo.Static.Scalar" BrowseName="1:Scalar">
        <DisplayName>Scalar</DisplayName>
        <References>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.Boolean</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.Byte</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.ByteString</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.DateTime</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.Double</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.Duration</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.Enumeration</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.Float</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.Guid</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.Int16</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.Int32</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.Int64</Reference>
            <!-- <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.Integer</Reference> -->
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.LocalizedText</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.NodeId</Reference>
            <!-- <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.Number</Reference> -->
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.QualifiedName</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.SByte</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.String</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.UInt16</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.UInt32</Reference>
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.UInt64</Reference>
            <!-- <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.UInteger</Reference> -->
            <!-- <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.Variant</Reference> -->
            <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar.XmlElement</Reference>
            <Reference ReferenceType="HasTypeDefinition">i=61</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static</Reference>
            </References>
    </UAObject>
    <UAVariable DataType="Boolean" NodeId="ns=1;s=Demo.Static.Scalar.Boolean" BrowseName="1:Boolean" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Boolean</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:Boolean>false</uax:Boolean>
        </Value>
    </UAVariable>
    <UAVariable DataType="Byte" NodeId="ns=1;s=Demo.Static.Scalar.Byte" BrowseName="1:Byte" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Byte</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:Byte>1</uax:Byte>
        </Value>
    </UAVariable>
    <UAVariable DataType="ByteString" NodeId="ns=1;s=Demo.Static.Scalar.ByteString" BrowseName="1:ByteString" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>ByteString</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:ByteString>EjSrzQ==</uax:ByteString>
        </Value>
    </UAVariable>
    <UAVariable DataType="DateTime" NodeId="ns=1;s=Demo.Static.Scalar.DateTime" BrowseName="1:DateTime" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>DateTime</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:DateTime>2015-05-27T14:03:25Z</uax:DateTime>
        </Value>
    </UAVariable>
    <UAVariable DataType="Double" NodeId="ns=1;s=Demo.Static.Scalar.Double" BrowseName="1:Double" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Double</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:Double>3.14</uax:Double>
        </Value>
    </UAVariable>
    <UAVariable DataType="Duration" NodeId="ns=1;s=Demo.Static.Scalar.Duration" BrowseName="1:Duration" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Duration</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:Double>9.999</uax:Double>
        </Value>
    </UAVariable>
    <UAVariable DataType="i=852" NodeId="ns=1;s=Demo.Static.Scalar.Enumeration" BrowseName="1:Enumeration" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Enumeration</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:Int32>1</uax:Int32>
        </Value>
    </UAVariable>
    <UAVariable DataType="Float" NodeId="ns=1;s=Demo.Static.Scalar.Float" BrowseName="1:Float" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Float</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:Float>12.34</uax:Float>
        </Value>
    </UAVariable>
    <UAVariable DataType="Guid" NodeId="ns=1;s=Demo.Static.Scalar.Guid" BrowseName="1:Guid" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Guid</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:Guid>
                <uax:String>EA292DEC-0F79-43F0-84FF-2E4AC0150919</uax:String>
            </uax:Guid>
        </Value>
    </UAVariable>
    <UAVariable DataType="Int16" NodeId="ns=1;s=Demo.Static.Scalar.Int16" BrowseName="1:Int16" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Int16</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:Int16>0</uax:Int16>
        </Value>
    </UAVariable>
    <UAVariable DataType="Int32" NodeId="ns=1;s=Demo.Static.Scalar.Int32" BrowseName="1:Int32" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Int32</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:Int32>0</uax:Int32>
        </Value>
    </UAVariable>
    <UAVariable DataType="Int64" NodeId="ns=1;s=Demo.Static.Scalar.Int64" BrowseName="1:Int64" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Int64</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:Int64>0</uax:Int64>
        </Value>
    </UAVariable>
    <!-- <UAVariable DataType="Integer" NodeId="ns=1;s=Demo.Static.Scalar.Integer" BrowseName="1:Integer" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Integer</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:Int16>321</uax:Int16>
        </Value>
    </UAVariable> -->
    <UAVariable DataType="LocalizedText" NodeId="ns=1;s=Demo.Static.Scalar.LocalizedText" BrowseName="1:LocalizedText" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>LocalizedText</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:LocalizedText>
                <uax:Locale>DE</uax:Locale>
                <uax:Text>Hallo Welt</uax:Text>
            </uax:LocalizedText>
        </Value>        
    </UAVariable>
    <UAVariable DataType="NodeId" NodeId="ns=1;s=Demo.Static.Scalar.NodeId" BrowseName="1:NodeId" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>NodeId</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:NodeId>
                <uax:Identifier>ns=3;s=ThisIsAStringIdentifier</uax:Identifier>
            </uax:NodeId>
        </Value> 
    </UAVariable>
    <!-- <UAVariable DataType="Number" NodeId="ns=1;s=Demo.Static.Scalar.Number" BrowseName="1:Number" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Number</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:Float>12.34</uax:Float>
        </Value>
    </UAVariable> -->
    <UAVariable DataType="QualifiedName" NodeId="ns=1;s=Demo.Static.Scalar.QualifiedName" BrowseName="1:QualifiedName" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>QualifiedName</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:QualifiedName>
                <uax:NamespaceIndex>4</uax:NamespaceIndex>
                <uax:Name>A qualified Name</uax:Name>
            </uax:QualifiedName>
        </Value>
    </UAVariable>
    <UAVariable DataType="SByte" NodeId="ns=1;s=Demo.Static.Scalar.SByte" BrowseName="1:SByte" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>SByte</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:SByte>0</uax:SByte>
        </Value>
    </UAVariable>
    <UAVariable DataType="String" NodeId="ns=1;s=Demo.Static.Scalar.String" BrowseName="1:String" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>String</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:String>Take Care</uax:String>
        </Value>
    </UAVariable>
    <UAVariable DataType="UInt16" NodeId="ns=1;s=Demo.Static.Scalar.UInt16" BrowseName="1:UInt16" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>UInt16</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:UInt16>0</uax:UInt16>
        </Value>
    </UAVariable>
    <UAVariable DataType="UInt32" NodeId="ns=1;s=Demo.Static.Scalar.UInt32" BrowseName="1:UInt32" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>UInt32</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:UInt32>0</uax:UInt32>
        </Value>
    </UAVariable>
    <UAVariable DataType="UInt64" NodeId="ns=1;s=Demo.Static.Scalar.UInt64" BrowseName="1:UInt64" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>UInt64</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:UInt64>0</uax:UInt64>
        </Value>
    </UAVariable>
    <!-- <UAVariable DataType="UInteger" NodeId="ns=1;s=Demo.Static.Scalar.UInteger" BrowseName="1:UInteger" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>UInteger</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:UInt32>433221</uax:UInt32>
        </Value>
    </UAVariable> -->
    <!-- <UAVariable DataType="i=24" NodeId="ns=1;s=Demo.Static.Scalar.Variant" BrowseName="1:Variant" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>Variant</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:Int32>-4455</uax:Int32>
        </Value>
    </UAVariable> -->
    <UAVariable DataType="XmlElement" NodeId="ns=1;s=Demo.Static.Scalar.XmlElement" BrowseName="1:XmlElement" UserAccessLevel="3" AccessLevel="3">
        <DisplayName>XmlElement</DisplayName>
        <References>
            <Reference ReferenceType="HasTypeDefinition">i=63</Reference>
            <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.Static.Scalar</Reference>
        </References>
        <Value>
            <uax:XmlElement><foo>bar</foo></uax:XmlElement>
        </Value>
    </UAVariable>
    <UAObject NodeId="ns=1;i=15182" BrowseName="1:http://github.com/awcullen/opcua//testserver/" >
    <DisplayName>http://github.com/awcullen/opcua//testserver/</DisplayName>
    <References>
      <Reference ReferenceType="HasProperty">ns=1;i=15183</Reference>
      <Reference ReferenceType="HasProperty">ns=1;i=15184</Reference>
      <Reference ReferenceType="HasProperty">ns=1;i=15185</Reference>
      <Reference ReferenceType="HasProperty">ns=1;i=15186</Reference>
      <Reference ReferenceType="HasProperty">ns=1;i=15187</Reference>
      <Reference ReferenceType="HasProperty">ns=1;i=15188</Reference>
      <Reference ReferenceType="HasProperty">ns=1;i=15189</Reference>
      <Reference ReferenceType="HasTypeDefinition">i=11616</Reference>
      <Reference ReferenceType="HasComponent" IsForward="false">i=11715</Reference>
    </References>
  </UAObject>
  <UAVariable NodeId="ns=1;i=15183" BrowseName="NamespaceUri" DataType="String" UserAccessLevel="1" AccessLevel="1">
    <DisplayName>NamespaceUri</DisplayName>
    <Description>The URI of the namespace.</Description>
    <References>
      <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
      <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=15182</Reference>
    </References>
    <Value>
      <String xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">http://github.com/awcullen/opcua//testserver/</String>
    </Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=15184" BrowseName="NamespaceVersion" DataType="String" UserAccessLevel="1" AccessLevel="1">
    <DisplayName>NamespaceVersion</DisplayName>
    <Description>The human readable string representing version of the namespace.</Description>
    <References>
      <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
      <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=15182</Reference>
    </References>
    <Value>
      <String xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">1.03</String>
    </Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=15185" BrowseName="NamespacePublicationDate" DataType="DateTime" UserAccessLevel="1" AccessLevel="1">
    <DisplayName>NamespacePublicationDate</DisplayName>
    <Description>The publication date for the namespace.</Description>
    <References>
      <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
      <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=15182</Reference>
    </References>
    <Value>
      <uax:DateTime>2019-03-29T12:00:00Z</uax:DateTime>
    </Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=15186" BrowseName="IsNamespaceSubset" DataType="Boolean" UserAccessLevel="1" AccessLevel="1">
    <DisplayName>IsNamespaceSubset</DisplayName>
    <Description>If TRUE then the server only supports a subset of the namespace.</Description>
    <References>
      <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
      <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=15182</Reference>
    </References>
    <Value>
      <Boolean xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">false</Boolean>
    </Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=15187" BrowseName="StaticNodeIdTypes"  DataType="i=256" ValueRank="1" UserAccessLevel="1" AccessLevel="1">
    <DisplayName>StaticNodeIdTypes</DisplayName>
    <Description>A list of IdTypes for nodes which are the same in every server that exposes them.</Description>
    <References>
      <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
      <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=15182</Reference>
    </References>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=15188" BrowseName="StaticNumericNodeIdRange" DataType="i=291" ValueRank="1" UserAccessLevel="1" AccessLevel="1">
    <DisplayName>StaticNumericNodeIdRange</DisplayName>
    <Description>A list of ranges for numeric node ids which are the same in every server that exposes them.</Description>
    <References>
      <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
      <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=15182</Reference>
    </References>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=15189" BrowseName="StaticStringNodeIdPattern" DataType="String" UserAccessLevel="1" AccessLevel="1">
    <DisplayName>StaticStringNodeIdPattern</DisplayName>
    <Description>A regular expression which matches string node ids are the same in every server that exposes them.</Description>
    <References>
      <Reference ReferenceType="HasTypeDefinition">i=68</Reference>
      <Reference ReferenceType="HasProperty" IsForward="false">ns=1;i=15182</Reference>
    </References>
  </UAVariable>
  <UAView NodeId="ns=1;s=Demo.View1" BrowseName="1:View1" >
    <DisplayName>View1</DisplayName>
    <References>
      <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Arrays</Reference>
      <Reference ReferenceType="Organizes" IsForward="false">i=87</Reference>
    </References>
  </UAView>
  <UAView NodeId="ns=1;s=Demo.View2" BrowseName="1:View2" >
    <DisplayName>View2</DisplayName>
    <References>
      <Reference ReferenceType="Organizes">ns=1;s=Demo.Static.Scalar</Reference>
      <Reference ReferenceType="Organizes" IsForward="false">i=87</Reference>
    </References>
  </UAView>
  <UAView NodeId="ns=1;s=Demo.NodeClasses.View1" BrowseName="1:View1" >
    <DisplayName>View1</DisplayName>
    <References>
      <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.NodeClasses</Reference>
    </References>
  </UAView>
  <UAView NodeId="ns=1;s=Demo.NodeClasses.View2" BrowseName="1:View2" >
    <DisplayName>View2</DisplayName>
    <References>
      <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.NodeClasses.View1</Reference>
    </References>
  </UAView>
  <UAView NodeId="ns=1;s=Demo.NodeClasses.View3" BrowseName="1:View3" >
    <DisplayName>View3</DisplayName>
    <References>
      <Reference ReferenceType="Organizes" IsForward="false">ns=1;s=Demo.NodeClasses.View1</Reference>
    </References>
  </UAView>
</UANodeSet>
`
