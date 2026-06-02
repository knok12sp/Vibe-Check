import React from "react";
import DOMPurify from "dompurify";

export default function Home({ userInput }: { userInput: string }) {
  return (
    <div>
      <div dangerouslySetInnerHTML={{ __html: userInput }} />
      <div ref={(el) => { if (el) el.innerHTML = userInput; }} />
    </div>
  );
}
