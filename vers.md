Stored Cross-Site Scripting (XSS) vulnerability in Simple Content Templates for Blog Posts & Pages WordPress plugin version 2.2.7.

Vulnerability Details:
The plugin stores user-supplied content (template title, content, excerpt) in the database without proper sanitization. When an administrator creates a template containing JavaScript code and uses the "Load Template" feature to insert the template content into a new post, the malicious JavaScript executes in the browser.

Attack Vector:
1. Attacker (with administrator/editor privileges) creates a template with JavaScript in the title field
2. When the template is loaded via the "Load Template" button, the JavaScript executes
3. This can lead to session hijacking, admin actions impersonation, or data theft

Affected Components:
- Template title field

Proof of Concept:
1. Create a new Content Template with title: 

   ```js
   <img src=x onerror=alert(document.cookie)>
   ```

   ![image-1](./screenshots/test1.png)

2. Publish the template
   ![image-2](./screenshots/test2.png)

3. Go to Posts → Add New

   ![image-3](./screenshots/test3.png)

4. Select the template from the Simple Content Templates dropdown

5. Click "Load Template"
   ![image-4](./screenshots/test4.png)

6. The JavaScript alert will trigger
   ![image-5](./screenshots/test5.png)

   ![image-6](./screenshots/test6.png)

Recommendation:

- Sanitize template input using wp_kses() on save
- Escape template output using esc_html()/esc_attr() on display
- Limit template creation privileges to trusted administrators only
