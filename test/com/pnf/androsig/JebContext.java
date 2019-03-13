/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig;

import com.pnfsoftware.jeb.core.ICoreContext;
import com.pnfsoftware.jeb.core.IEnginesContext;
import com.pnfsoftware.jeb.core.JebCoreService;
import com.pnfsoftware.jeb.core.dao.IDataProvider;
import com.pnfsoftware.jeb.core.dao.IFileDatabase;
import com.pnfsoftware.jeb.core.dao.IFileStore;
import com.pnfsoftware.jeb.core.dao.impl.DataProvider;
import com.pnfsoftware.jeb.core.dao.impl.JEB2FileDatabase;
import com.pnfsoftware.jeb.core.dao.impl.SimpleFSFileStore;
import com.pnfsoftware.jeb.core.exceptions.JebException;
import com.pnfsoftware.jeb.core.properties.IConfiguration;
import com.pnfsoftware.jeb.core.properties.impl.ConfigurationMemoryMap;

/**
 * @author Cedric Lucas
 *
 */
public class JebContext {
    //private static IEnginesContext engctx = null;

    public static IEnginesContext getEnginesContext() throws JebException {
        return getEnginesContext("testdata/out");
        //if(engctx == null) {
        //    engctx = getEnginesContext("testdata/out");
        //}
        //return engctx;
    }

    private static IEnginesContext getEnginesContext(String baseDir) throws JebException {
        // create or retrieve a core context (engines container)
        String licenseKey = System.getProperty("licenseKey");
        if(licenseKey == null) {
            throw new IllegalStateException("Missing VM argument -DlicenseKey=123456789");
        }
        ICoreContext core = JebCoreService.getInstance(licenseKey);

        // create an engines context (project container)
        IFileDatabase projectdb = new JEB2FileDatabase(baseDir);
        IFileStore filestore = new SimpleFSFileStore(baseDir);
        IFileStore pluginfilestore = filestore;

        IConfiguration config = new ConfigurationMemoryMap();
        IDataProvider dataProvider = new DataProvider(null, projectdb, filestore, pluginfilestore, null, config);
        return core.createEnginesContext(dataProvider, null);
    }

}
