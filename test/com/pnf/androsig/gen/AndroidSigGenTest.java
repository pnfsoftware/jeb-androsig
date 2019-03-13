/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.gen;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;

import org.junit.Test;

import com.pnf.androsig.JebContext;
import com.pnfsoftware.jeb.client.Licensing;
import com.pnfsoftware.jeb.core.Artifact;
import com.pnfsoftware.jeb.core.IArtifact;
import com.pnfsoftware.jeb.core.IEnginesContext;
import com.pnfsoftware.jeb.core.IRuntimeProject;
import com.pnfsoftware.jeb.core.exceptions.JebException;
import com.pnfsoftware.jeb.core.input.FileInput;
import com.pnfsoftware.jeb.util.io.IO;

/**
 * @author Cedric Lucas
 *
 */
public class AndroidSigGenTest {

    @Test
    public void testGenSigGen() throws JebException, IOException {
        File generated = new File("testdata/out/android_sigs/sig-gen-test_dex.sig");
        try {
            IEnginesContext context = JebContext.getEnginesContext();
            context.getDataProvider().getPluginStore().getStoreLocation();
            IRuntimeProject prj = context.loadProject("sig-gen-test.dex");
            File file = new File("testdata/dex", "sig-gen-test.dex");
            IArtifact artifact = new Artifact(file.getName(), new FileInput(file));
            /*ILiveArtifact art =*/ prj.processArtifact(artifact);

            AndroidSigGenPlugin plugin = new AndroidSigGenPlugin();
            plugin.execute(context, new HashMap<>());

            // assertions
            byte[] data = IO.readFile(generated);
            String content = new String(data, "UTF-8");
            content = content.replace(Licensing.user_name, "Nicolas Falliere");
            IO.writeFile(generated, content);
            assertTrue(IO.compareFiles(generated, new File("testdata/sig/sig-gen-test.sig")));
        }
        finally {
            // clean up
            if(generated.exists()) {
                generated.delete();
            }
        }
    }
}
