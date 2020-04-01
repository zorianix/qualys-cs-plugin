package com.qualys.plugins.containerSecurity.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.commons.lang.StringUtils;

public class Helper {
    public static String GET_IMAGE_LIST_API_PATH_FORMAT = "/csapi/v1.2/images?pageNumber=0&pageSize=10&sort=created";
    public static String GET_SCAN_RESULT_API_PATH_FORMAT = "/csapi/v1.2/images/%s"; 
    public static String CVE_REGEX = "CVE-\\d{4}-\\d{4,7}";
    
    public static String IMAGE_ID_REGEX = "^([A-Fa-f0-9]{12}|[A-Fa-f0-9]{64})$";
    public static String IMAGE_NAME_REGEX = "^(?:(?=[^:\\/]{4,253})(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*(?::[0-9]{1,5})?/)?((?![:\\/._-])(?:[a-z0-9._-]*)(?<![:\\/._-])(?:/(?![._-])[a-z0-9._-]+(?<![._-]))*)(?::(?![.-])[a-zA-Z0-9_.-]{1,128})?$";
	public static String IMAGE_ENV_VAR = "\\$\\{(.*?)}";
	public static List<String> TAGGING_STATUS = new ArrayList<String>();
    
    public static boolean isValidCVEList(String cveList) {
    	if(cveList != null && !StringUtils.isBlank(cveList)) {
    		List<String> cves = Arrays.asList(cveList.split(","));
    		Pattern patt = Pattern.compile(CVE_REGEX);
    		for(String el: cves) {
                Matcher matcher = patt.matcher(el);
                if (!(matcher.matches())) {
                    return false;
                }
    		}
    	}
    	return true;
    }
    public static void createNewFile(String rootDir, String filename, String content, PrintStream buildLogger) {
  	  	   	
    	 File f = new File(rootDir + File.separator + filename + ".json");
	    if(!f.getParentFile().exists()){
	        f.getParentFile().mkdirs();
	    }

	    if(!f.exists()){
	        try {
	            f.createNewFile();
	        } catch (Exception e) {
	            e.printStackTrace();
	            buildLogger.println("Failed creating file " + filename + ", reason =" + e.getMessage());
	        }
	    }
	    try {
	        File dir = new File(f.getParentFile(), f.getName());
	        PrintWriter writer = new PrintWriter(dir);
	        writer.print(content);
	        writer.close();
	    } catch (FileNotFoundException e) {
	    	e.printStackTrace();
	    	buildLogger.println("Failed writing to file " + filename + ", reason =" + e.getMessage());
	    }
    }
    
    public static void createZip(String zipFile, String srcDir, PrintStream buildLogger) {
    	        
        try {
             
            // create byte buffer
            byte[] buffer = new byte[1024];
            FileOutputStream fos = new FileOutputStream(zipFile);
 
            ZipOutputStream zos = new ZipOutputStream(fos);
 
            File dir = new File(srcDir);
 
            //Get only .txt files
            File[] files = dir.listFiles(new FilenameFilter() { 
                public boolean accept(File dir, String filename)
                	{ return filename.endsWith(".json"); }
            	} );
            
            for (int i = 0; i < files.length; i++) {
            		System.out.println("Adding file: " + files[i].getName());
            		
            		FileInputStream fis = new FileInputStream(files[i]);
            		
            		zos.putNextEntry(new ZipEntry(files[i].getName()));
            		int length;
            		while ((length = fis.read(buffer)) > 0) {
            			zos.write(buffer, 0, length);
            		}
            		zos.closeEntry();
            		
            		fis.close();
            		//delete file
            		if(! files[i].getName().equals("qualys_images_summary.json"))
            			files[i].delete();
            }
            zos.close();
        }
        catch (IOException ioe) {
        	buildLogger.println("Error creating zip file" + ioe);
        }
    }
}
