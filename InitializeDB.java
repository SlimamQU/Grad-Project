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

		System.out.println("tessstststt");
		System.err.println(args[0]);
		setupDB(Integer.parseInt(args[0]));

		

	}



	public static void setupDB(int year) {



		try {

			//String filename = "nvdcve-2008.xml";



			Connection con = getConnection();

			Statement sql = con.createStatement();

			sql.execute("use nvd;");

			sql.execute("drop table if exists nvd");                                                                                                                                                                                                        //,primary key(id)

			sql.execute("create table nvd(id varchar(20) not null,soft varchar(160) not null default 'ndefined',rng varchar(100) not null default 'undefined',lose_types varchar(100) not null default 'undefind',severity varchar(20) not null default 'unefined',access varchar(20) not null default 'unefined');");

	

			SAXReader saxReader = new SAXReader();

			

			int counttot = 0;

			for(int ct=2002;ct<=year;ct++){

			    //String fname="/transient/mulval/oval/nvd/nvdcve-"+Integer.toString(ct)+".xml";
				String fname="nvd_xml_files/nvdcve-1.1-"+Integer.toString(ct)+".json";

        		File file = new File(fname);

				try
				{
					String content = new String(Files.readAllBytes(Paths.get(file.toURI())));
            		JSONObject jsonc = new JSONObject(content);
            		String cveName = jsonc.getString("CVE_data_type");
            		System.out.println("CVE : "+cveName.toString());
					String numCVEs = jsonc.getString("CVE_data_numberOfCVEs");
					System.out.println("Number of CVEs : "+numCVEs.toString());
					JSONArray cveItems = jsonc.getJSONArray("CVE_Items");
					int count = 0;
					for (int i=0;i<10;i++){

						count++;
						counttot++;
            		    JSONObject itemsO = cveItems.getJSONObject(i);
            		    JSONObject cveData = itemsO.getJSONObject("cve");
            		    JSONObject cveMeta = cveData.getJSONObject("CVE_data_meta");
            		    String cveID = cveMeta.getString("ID");
            		    // System.out.println("CVE : "+cveID.toString());
            		    JSONObject impact = itemsO.getJSONObject("impact");
            		    try {
            		    	JSONObject baseV2 = impact.getJSONObject("baseMetricV2");
            		    	JSONObject cvssV2 = baseV2.getJSONObject("cvssV2");
            		    	String rge = cvssV2.getString("accessVector");
            		    	String access = cvssV2.getString("vectorString");
            		    	String severity = baseV2.getString("severity");
            		    	String sftw = "Unknown";
            		    	String lose_types = "other";
            		       	System.out.println("CVE: "+cveID.toString()+" || SFTW: "+sftw.toString()+" || Range: "+rge.toString()+" || loss_type: "+lose_types.toString()+" || Severity: "+severity.toString()+" || Access: "+access.charAt(8));
            		       	String insert = "insert nvd values('" + cveID.toString() + "','"+ sftw.toString() + "','" + rge.toString() + "','" + lose_types.toString() + "','" + severity.toString()+ "','" + access.charAt(8)+"')";
            		       	sql.execute(insert);

            		    } catch (Exception ec) {
            		    	System.out.println("Error : "+ec);
                			String baseV2 = "N/A";
                			String severity = "N/A";
                			String rge = "N/A";
                			String access = "N/A------";
                			String sftw = "Unknown";
                			String lose_types = "other";
                		   	System.out.println("CVE: "+cveID.toString()+" || SFTW: "+sftw.toString()+" || Range: "+rge.toString()+" || loss_type: "+lose_types.toString()+" || Severity: "+severity.toString()+" || Access: "+access.charAt(8));

                		   	String insert = "insert nvd values('" + cveID.toString() + "','"+ sftw.toString() + "','" + rge.toString() + "','" + lose_types.toString() + "','" + severity.toString()+ "','" + access.charAt(8)+"')";
            		       	sql.execute(insert);
            			}
            		}
            		System.out.println("Number of CVE : "+count);
				} catch (Exception e) {
					System.out.println(e);
				}
			}
			System.out.println("Total "+counttot+" of CVE has been added to DataBase");
			sql.close();

			con.close();

			

		} catch (java.lang.ClassNotFoundException e) {

			System.err.println("ClassNotFoundException:" + e.getMessage());
			System.out.println(e);

		} catch (SQLException ex) {

			System.err.println("SQLException:" + ex.getMessage());
			System.out.println(ex);

		// } catch (DocumentException e) {

		// 	System.out.println(e);

		// 	e.printStackTrace();

		} catch (IOException e) {

			// TODO Auto-generated catch block
			System.out.println(e);
			e.printStackTrace();

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

