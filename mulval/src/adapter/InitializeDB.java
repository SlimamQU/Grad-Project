/*
Create a database storing the NVD data
Author(s) : Su Zhang, Xinming Ou
Copyright (C) 2011, Argus Cybersecurity Lab, Kansas State University

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
import org.json.*;

import java.util.regex.*;

import java.sql.*;
import javax.sql.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;



import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.dom4j.io.XMLWriter;



public class InitializeDB {

	/*public static Connection getConnection() throws SQLException,

			java.lang.ClassNotFoundException {

		String url = "jdbc:mysql://localhost:3306/mulvalDB";

		Class.forName("com.mysql.jdbc.Driver");

		String userName = "root";

		String password = "";



		Connection con = DriverManager.getConnection(url, userName, password);

		return con;

	}*/

	public static Connection getConnection() throws SQLException,

	java.lang.ClassNotFoundException, IOException {

//String url = "jdbc:mysql://localhost:3306/mulvalDB";

Class.forName("com.mysql.jdbc.Driver");

//String userName = "root";

//String password = "";

String url="";

String userName="";

String password="";
String MulvalRootEnv = System.getenv("MULVALROOT");

//System.out.println(MulvalRootEnv);

//File f = new File(MulvalRootEnv + "/src/dataPreProcessing/translator/config.txt");

File f= new File("config.txt");

String path = f.getPath();



	

	BufferedReader breader= new BufferedReader(new FileReader(path));

	

	url=breader.readLine();

	userName=breader.readLine();

	password=breader.readLine();

	Connection con = DriverManager.getConnection(url, userName, password);

	return con;	

}



	public static void main(String[] args) {

		// System.err.println(args[0]);
		setupDB(Integer.parseInt(args[0]));

		

	}



	public static void setupDB(int year) {

		ArrayList<String> errCollector = new ArrayList<String>();


		try {

			//String filename = "nvdcve-2008.xml";



			Connection con = getConnection();

			Statement sql = con.createStatement();

			sql.execute("use nvd;");

			sql.execute("drop table if exists nvd");                                                                                                                                                                                                        //,primary key(id)

			sql.execute("create table nvd(id varchar(20) not null,soft varchar(10000) not null default 'ndefined',rng varchar(100) not null default 'undefined',lose_types varchar(100) not null default 'undefind',severity varchar(20) not null default 'unefined',baseScore varchar(5) not null ,access varchar(20) not null default 'unefined',exploitability varchar(5) not null );");

	

			SAXReader saxReader = new SAXReader();

			

			int counttot = 0;

			for(int ct=2002;ct<=year;ct++){

				String fname="nvd_xml_files/nvdcve-1.1-"+Integer.toString(ct)+".json";

        		File file = new File(fname);

				try
				{
					String content = new String(Files.readAllBytes(Paths.get(file.toURI())));
            		JSONObject jsonc = new JSONObject(content);
            		String cveName = jsonc.getString("CVE_data_type");
            		// System.out.println("CVE : "+cveName.toString());
					String numCVEs = jsonc.getString("CVE_data_numberOfCVEs");
					System.out.println("Number of CVEs : "+numCVEs.toString()+" at "+ fname.toString());
					JSONArray cveItems = jsonc.getJSONArray("CVE_Items");
					int count = 0;
					for (int i=0;i<cveItems.length();i++){
					// for (int i=0;i<500;i++){ // testing

						String cveID="";
						// String baseV2 = "";
                		String severity = "";
                		String req = "";
                		String rge = "";
              			String access = "--------------";
                		// String sftw = "";
                		// String lose_types = "";
						count++;
						counttot++;
            		    JSONObject itemsO = cveItems.getJSONObject(i);
            		    JSONObject cveData = itemsO.getJSONObject("cve");
            		    JSONObject cveMeta = cveData.getJSONObject("CVE_data_meta");
            		    cveID = cveMeta.getString("ID");
            		    JSONObject impact = null ;
            		    JSONObject configration = null ;
            		    JSONArray nodes = null;
            		    JSONObject nodeitems = null;
           		    	JSONObject baseV = null ;
           		    	JSONArray children = null;
           		    	JSONObject childrenitems = null;
           		    	JSONArray cpe_match = null;
           		    	JSONArray child_cpe = null;
           		    	String cpe23Uri = null;
           		    	String lose_types = "" ;
           		    	String lose_type_avail = "";
           		    	String lose_type_conf = "";
           		    	String lose_type_int = "";
           		    	String baseScore = "";
           		    	String exploitability = "";
           		    	Double tempInt = 0.00 ;
           		    	JSONObject child_cpe_items = null;
           		    	JSONObject cpe_match_child = null;
           		    	ArrayList<String> sftw = new ArrayList<String>();

            		    // JSONObject impact = itemsO.getJSONObject("impact");
               		    // JSONObject configration = itemsO.getJSONObject("configurations");


            		    try {
            		    	// not null 
            		    	if (!itemsO.getJSONObject("impact").isEmpty()) {
            		    		// System.out.println("not Empty");
            		    		impact = itemsO.getJSONObject("impact");
            		    		if (impact.has("baseMetricV2") && !impact.isNull("baseMetricV2") && !impact.has("baseMetricV3")) {
            		    			// System.out.println("baseV2 is there ");
            		    			baseV = impact.getJSONObject("baseMetricV2");

            		    			// exploitability score
            		    			if (baseV.has("exploitabilityScore")){
            		    					tempInt = 0.00;
            		    					tempInt = baseV.getDouble("exploitabilityScore");
            		    					exploitability = "" + tempInt;
            		    					// System.out.println("exploitability score is : "+exploitability);
            		    				}
            		    			if (baseV.has("cvssV2") && !baseV.isNull("cvssV2")) {
            		    				// System.out.println("cvssV2 is there ");
            		    				JSONObject cvssV2 = baseV.getJSONObject("cvssV2");

            		    				// base score
            		    				if (cvssV2.has("baseScore")){
            		    					tempInt = 0.00;
            		    					tempInt = cvssV2.getDouble("baseScore");
            		    					baseScore = "" + tempInt;
            		    					// System.out.println("base score is : "+baseScore);
            		    				}

            		    				// access vector 
            		    				if (cvssV2.has("accessVector")) {
            		    					// System.out.println("accessVector is there ");
            		    					// String rge = cvssV2.getString("accessVector"); org 
            		    					String temp_rge = cvssV2.getString("accessVector");
            		    					// System.out.println("temp_rge is : "+temp_rge);
            		    					if (temp_rge.equals("NETWORK")) {
            		    						rge = "remoteExploit";
            		    						
            		    						if (!baseV.isNull("userInteractionRequired")) {
            		    							if (baseV.getBoolean("userInteractionRequired")==true) {
            		    								// System.out.println("req is true");
            		    								req = "-user_action_req";
            		    								rge += req ;
            		    								// System.out.println("range is : "+ rge);
            		    							}
            		    						}
            		    						//  else {
            		    						// 	System.out.print("Error : 00050");
            		    						// }
            		    					}
            		    					else if (temp_rge.equals("user_init")){
            		    						rge = "user_action_req";
            		    					}
            		    					else if (temp_rge.equals("ADJACENT_NETWORK")){
												rge = "lan";
            		    					}
											else if (temp_rge.equals("LOCAL")){
												rge = "local";
											}
											else
												rge = "other";
            		    				} else {
            		    					System.out.println("at CVE : "+cveID.toString()+" ERRRRRRRRRRRRRRRRRRROORRRROORROROR");
            		    				}

            		    				// vector string 
            		    				if (cvssV2.has("vectorString")) {
            		    					String temp_access = cvssV2.getString("vectorString");
            		    					char ac = temp_access.charAt(8);
											if (ac == 'L')
												access = "l";
											else if (ac == 'M')
												access = "m";
											else if (ac == 'H')
												access = "h";
											else ;
            		    				}

            		    				// severity
            		    				if (baseV.has("severity")) {
            		    					severity = baseV.getString("severity");
            		    				}

            		    				// TODO : edit for loss_type 
            		    				// sftw = "Unknown";
            		    				// lose_types = "other";
            		    				if (cvssV2.has("confidentialityImpact") && cvssV2.has("integrityImpact") && cvssV2.has("availabilityImpact")) {
            		    					lose_type_conf = cvssV2.getString("confidentialityImpact").toString();
            		    					lose_type_int = cvssV2.getString("integrityImpact").toString();
            		    					lose_type_avail = cvssV2.getString("availabilityImpact").toString();
            		    					String lose_type_temp = "";
            		    					if (!lose_type_avail.equals("NONE")){
            		    						lose_type_temp += "availability_loss" + "-";
            		    					}
            		    					if (!lose_type_int.equals("NONE")) {
            		    						lose_type_temp += "data_modification" + "-";
            		    					}
            		    					if (!lose_type_conf.equals("NONE")) {
            		    						lose_type_temp += "data_loss" + "-";
            		    					}
            		    					if (lose_type_conf.equals("NONE") && lose_type_int.equals("NONE") && lose_type_avail.equals("NONE") ) {
            		    						lose_type_temp = "other,";
            		    					}
            		    					lose_types = lose_type_temp.substring(0, lose_type_temp.length() - 1) ;
            		    					// System.out.println("at CVE : "+cveID+" | lose_type : "+lose_type_temp.substring(0, lose_type_temp.length() - 2));
            		    					
            		    					
            		    				}


            		    			}

            		    		// } else if (impact.has("baseMetricV2") && !impact.isNull("baseMetricV2")) {
            		    		// 	System.out.println("baseV2 is there but Null");
            		    		// } else if (impact.has("baseMetricV3") && impact.isNull("baseMetricV2")) {
            		    		} else if (impact.has("baseMetricV3") && !impact.isNull("baseMetricV3")) {

            		    			// System.out.println("baseV3 is there "+"at : "+cveID.toString());
            		    			// System.out.println("baseV2 is there ");
            		    			baseV = impact.getJSONObject("baseMetricV3");

            		    			// exploitability score
            		    			if (baseV.has("exploitabilityScore")){
            		    				   tempInt = 0.00;
            		    					tempInt = baseV.getDouble("exploitabilityScore");
            		    					exploitability = "" +tempInt;
            		    					// System.out.println("exploitability score is : "+exploitability);
            		    				}

            		    			// if (baseV.has("cvssV2") && !baseV.isNull("cvssV3")) { org 
            		    			if (baseV.has("cvssV3") && !baseV.isNull("cvssV3")) { // test 
            		    				// System.out.println("cvssV2 is there ");
            		    				JSONObject cvssV2 = baseV.getJSONObject("cvssV3");

            		    				// base score
            		    				if (cvssV2.has("baseScore")){
            		    					tempInt = 0.00;
            		    					tempInt = cvssV2.getDouble("baseScore");
            		    					baseScore = "" +tempInt;
            		    					// System.out.println("base score is : "+baseScore);
            		    				}

            		    				// access vector 
            		    				if (cvssV2.has("attackVector")) {
            		    					// System.out.println("accessVector is there ");
            		    					// String rge = cvssV2.getString("accessVector"); org 
            		    					String temp_rge = cvssV2.getString("attackVector");
            		    					// System.out.println("temp_rge is : "+temp_rge);
            		    					if (temp_rge.equals("NETWORK")) {
            		    						rge = "remoteExploit";
            		    						
            		    						if (!baseV.isNull("userInteraction")) {
            		    							if (baseV.getString("userInteraction").equals("REQUIRED")) {
            		    								// System.out.println("req is true");
            		    								req = "-user_action_req";
            		    								rge += req ;
            		    								// System.out.println("range is : "+ rge);
            		    							}
            		    						}
            		    						//  else {
            		    						// 	System.out.print("Error : 00050");
            		    						// }
            		    					}
            		    					else if (temp_rge.equals("user_init")){
            		    						rge = "user_action_req";
            		    					}
            		    					else if (temp_rge.equals("ADJACENT_NETWORK")){
												rge = "lan";
            		    					}
											else if (temp_rge.equals("LOCAL")){
												rge = "local";
											}
											else
												rge = "other";
            		    				} else {
            		    					System.out.println("at CVE : "+cveID.toString()+" ERRRRRRRRRRRRRRRRRRROORRRROORROROR");
            		    				}

            		    				// vector string 
            		    				if (cvssV2.has("vectorString")) {
            		    					String temp_access = cvssV2.getString("vectorString");
            		    					char ac = temp_access.charAt(17);
											if (ac == 'L')
												access = "l";
											else if (ac == 'M')
												access = "m";
											else if (ac == 'H')
												access = "h";
											else ;
            		    				}

            		    				// severity
            		    				if (cvssV2.has("baseSeverity")) {
            		    					severity = cvssV2.getString("baseSeverity");
            		    				}

            		    				// TODO : edit loss_type 
            		    				// sftw = "Unknown";
            		    				// lose_types = "other";
            		    				if (cvssV2.has("confidentialityImpact") && cvssV2.has("integrityImpact") && cvssV2.has("availabilityImpact")) {
            		    					// TODO : 
            		    					lose_type_conf = cvssV2.getString("confidentialityImpact").toString();
            		    					lose_type_int = cvssV2.getString("integrityImpact").toString();
            		    					lose_type_avail = cvssV2.getString("availabilityImpact").toString();
            		    					String lose_type_temp = "";
            		    					if (!lose_type_avail.equals("NONE")){
            		    						lose_type_temp += "availability_loss" + "-";
            		    					}
            		    					if (!lose_type_int.equals("NONE")) {
            		    						lose_type_temp += "data_modification" + "-";
            		    					}
            		    					if (!lose_type_conf.equals("NONE")) {
            		    						lose_type_temp += "data_loss" + "-";
            		    					}
            		    					if (lose_type_conf.equals("NONE") && lose_type_int.equals("NONE") && lose_type_avail.equals("NONE") ) {
            		    						lose_type_temp = "other,";
            		    					}
            		    					lose_types = lose_type_temp.substring(0, lose_type_temp.length() - 1);
            		    					// System.out.println("at CVE : "+cveID+" | lose_type : "+lose_type_temp.substring(0, lose_type_temp.length() - 2));
            		    					
            		    				}


            		    			}

            		    		}
            		    	}else if (itemsO.getJSONObject("impact").isEmpty()){
            		    		// System.out.println("impact is Empty" + itemsO.getJSONObject("impact"));
                				// severity = "N/A";
                				// rge = "N/A";
                				// access = "N/A------";
                				// sftw = "Unknown";
                				// lose_types = "other";
            		    	}

            		    	// configration 
            		    	if (!itemsO.getJSONObject("configurations").isEmpty()) {
   		               		    configration = itemsO.getJSONObject("configurations");
            		    		if (!configration.getJSONArray("nodes").isEmpty()) {

            		    			// System.out.println("nodes is not Empty");
            		    			nodes = configration.getJSONArray("nodes");
            		    			// for (int a=0;a<nodes.length();a++) {
   				            		    nodeitems = nodes.getJSONObject(0);
   				            		    
   				            		    // System.out.println("nodeitems : "+nodeitems);
   				            		    if (nodeitems.getJSONArray("children").isEmpty() && !nodeitems.getJSONArray("cpe_match").isEmpty()) {
   				            		    	// System.out.println("there is no children");
   				            		    	cpe_match = nodeitems.getJSONArray("cpe_match");
   				            		    		for (int z=0;z<cpe_match.length();z++) {
   				            		    			cpe_match_child = cpe_match.getJSONObject(z);
   				            		    			cpe23Uri = cpe_match_child.getString("cpe23Uri");
   				            		    			// System.out.println("cpe_match : "+cpe23Uri);
   				            		    			// System.out.println("cpe23Uri is : "+cpe23Uri);

   				            		    			// try to filter 
   				            		    			Pattern pattern = Pattern.compile("(?<=:o:|:a:|:h:)(\\S+)(?=\\\"|\\Z)");
    												Matcher matcher = pattern.matcher(cpe23Uri);
    												boolean matchFound = matcher.find();
    												if(matchFound) {
      													String temp = matcher.group(0);
      													// System.out.println("a : "+temp);
      													if (sftw.size() <= 129) {
      														sftw.add(temp);
      													}
    												} else {
      													System.out.println("Match not found \n Error : 00010");
    												}
   				            		    			
   				            		    			
   				            		    		}
   				            		    	// cpe_match = nodeitems.getJSONArray("cpe_match");
   				            		    	// System.out.println("cpe_match : "+cpe_match);
   				            		    	// System.out.println("is children null : "+nodeitems.getJSONArray("children").isEmpty());
   				            		    	// System.out.println("is cpe_match null : "+nodeitems.getJSONArray("cpe_match").isEmpty());
   				            		    } else if (!nodeitems.getJSONArray("children").isEmpty() && nodeitems.getJSONArray("cpe_match").isEmpty()) {
   				            		    	// System.out.println("children is there !!! ");
   				            		    	children = nodeitems.getJSONArray("children");
   				            		    	for (int x=0;x<children.length();x++) {
   				            		    		childrenitems = children.getJSONObject(x);
   				            		    		// System.out.println("childrenitems : "+childrenitems);
   				            		    		child_cpe = childrenitems.getJSONArray("cpe_match");
   				            		    		for (int y=0;y<child_cpe.length();y++) {
   				            		    			child_cpe_items = child_cpe.getJSONObject(y);
   				            		    			cpe23Uri = child_cpe_items.getString("cpe23Uri");

   				            		    			// System.out.println("children cpe_match : "+cpe23Uri);

   				            		    			// try to filter 
   				            		    			Pattern pattern = Pattern.compile("(?<=:o:|:a:|:h:)(\\S+)(?=\\\"|\\Z)");
    												Matcher matcher = pattern.matcher(cpe23Uri);
    												boolean matchFound = matcher.find();
    												if(matchFound) {
      													String temp = matcher.group(0);
      													// System.out.println("a : "+temp);
      													if (sftw.size() <= 129) {
      														sftw.add(temp);
      													}
    												} else {
      													System.out.println("Match not found \n Error : 00010");
    												}

   				            		    		}
   				            		    	
   				            		    	}
   				            		    	
   				            		    	// child_cpe = children.getJSONArray("cpe_match");
   				            		    	
   				            		    	// System.out.println("is children null : "+nodeitems.getJSONArray("children").isEmpty());
   				            		    	// System.out.println("is cpe_match null : "+nodeitems.getJSONArray("cpe_match").isEmpty());

   				            		    }
            		    			// } end of for nodes
            		    		} else {
            		    			// System.out.println(" ************************ \n *****************");
            		    			if (sftw.isEmpty()) {
            		    				sftw.add("-");
            		    			}

            		    		}
            		    		
            		    	}
            		    	// print number of elements in arr 
            		    	
            		    	// System.out.println("numebr of Attribute for CVE : "+cveID.toString()+" is "+sftw.size());

            		    	// System.out.println("software array : "+sftw);
            		       	// System.out.println("CVE: "+cveID.toString()+" || SFTW: "+sftw.toString()+" || Range: "+rge.toString()+" || loss_type: "+lose_types.toString()+" || Severity: "+severity.toString()+" || Access: "+access.toString());
   // /*print no software*/    System.out.println("CVE: "+cveID.toString()+" || Range: "+rge.toString()+" || loss_type: "+lose_types.toString()+" || Severity: "+severity.toString()+" || Access: "+access.toString()); 

            		       	// String insert = "insert nvd values('" + cveID.toString() + "','"+ sftw.toString() + "','" + rge.toString() + "','" + lose_types.toString() + "','" + severity.toString()+ "','" + baseScore.toString() +"','" + access.toString() +"','" + exploitability.toString() + "')";
            // /* no software*/String insert = "insert nvd values('" + cveID.toString() + "','"+ rge.toString() + "','" + lose_types.toString() + "','" + severity.toString()+ "','" + access.toString()+"')";
            		       	// System.out.println(insert);
            		       	// sql.execute(insert);
            		       	sql.execute("insert nvd values('" + cveID.toString() + "','"+ sftw.toString() + "','" + rge.toString() + "','" + lose_types.toString() + "','" + severity.toString()+ "','" + baseScore.toString() +"','" + access.toString() +"','" + exploitability.toString() + "')");
            		       	sftw.clear();
            		       	// System.out.println("after Empty : "+sftw);

            		    } catch (Exception ec) {
            		    	System.out.println("Error at CVE "+cveID.toString()+" : "+ec);
            		    	errCollector.add("Error 000 at CVE  : "+cveID.toString()+" - "+ec);
                			// String baseV = "N/A";
                			// String severity = "N/A";
                			// String rge = "N/A";
                			// String access = "N/A------";
                			// String sftw = "Unknown";
                			// String lose_types = "other";
                		   	// System.out.println("CVE: "+cveID.toString()+" || SFTW: "+sftw.toString()+" || Range: "+rge.toString()+" || loss_type: "+lose_types.toString()+" || Severity: "+severity.toString()+" || Access: "+access.charAt(8));

                		   	// String insert = "insert nvd values('" + cveID.toString() + "','"+ sftw.toString() + "','" + rge.toString() + "','" + lose_types.toString() + "','" + severity.toString()+ "','" + access.charAt(8)+"')";
            		       	// sql.execute(insert);
            			}
            		}
            		System.out.println("*"+count+" CVE has been added to DataBase");
				} catch (Exception e) {
					System.out.println(e);
					errCollector.add("Error 001 at CVE  : "+e);
				}
			}
			System.out.println("Total "+counttot+" of CVE has been added to DataBase");
			System.out.println(errCollector);
			sql.close();

			con.close();

			

		} catch (java.lang.ClassNotFoundException e) {

			System.err.println("ClassNotFoundException:" + e.getMessage());
			System.out.println(e);
			errCollector.add("Error 002 at CVE  : "+e);

		} catch (SQLException ex) {

			System.err.println("SQLException:" + ex.getMessage());
			System.out.println(ex);
			errCollector.add("Error 003 at CVE  : "+ex);
		// } catch (DocumentException e) {

		// 	System.out.println(e);

		// 	e.printStackTrace();

		} catch (IOException e) {

			// TODO Auto-generated catch block
			System.out.println(e);
			e.printStackTrace();
			errCollector.add("Error 004 at CVE  : "+e);

		}
	}



	public static void clearEntryWithVulsoft(String filename) {



		try {



			SAXReader saxReader = new SAXReader();

			Document document = saxReader.read(filename);

			



			List soft = document

					.selectNodes("/*[local-name(.)='nvd']/*[local-name(.)='entry']/*[local-name(.)='vuln_soft']");

			Iterator sft = soft.iterator(); 

			Element nvd = (Element) document

					.selectSingleNode("/*[local-name(.)='nvd']");



			while (sft.hasNext()) {



				Element vsft = (Element) sft.next();

				nvd.remove(vsft.getParent());

				XMLWriter output = new XMLWriter(new FileWriter(filename));//

				output.write(document);

				output.flush();

				output.close();



			}



		} catch (Exception e) {



			e.printStackTrace();

		}

	}

}

